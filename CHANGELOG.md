# Release Notes for Auth Kit

## 1.5.0 - 2026-07-17

### Added
- `Audit::EVENT_AFTER_RECORD`, fired once after `Audit::record()` fans an
  `AuthEvent` out to its registered sinks, carrying the recorded event on a new
  `events\AuditRecordEvent`. It lets a downstream observer (the Audit Kit
  bridge) relay authentication events onto the neutral audit bus without
  registering as an Auth Kit sink. Purely additive and zero behaviour change:
  the event fires after the existing sink fan-out, `AuthEvent` and the sink
  interface are untouched, and with no listener attached it is a cheap no-op.

## 1.4.0 - 2026-07-16

### Added
- Per-consumer issuance scoping, so two plugins sharing the token store no
  longer interfere: `issueMagicLink()` / `issueOtp()` / `issueRegistration()`
  accept a per-issuance options array (`origin`, `route`, `ttl`, `digits`,
  `maxAttempts`, `perEmailLimit`, `perEmailWindow`) that overrides the shared
  service defaults for that one issuance; unknown or malformed options are
  refused loudly. The new `origin` label (the consuming plugin's handle) is
  stored on the token, and every consume (`consumeMagicLink()` /
  `consumeOtp()` / `consumeRegistration()`) matches it strictly: a token
  presented at another consumer's endpoint is refused and left unburned for
  its rightful one, per-origin OTPs neither supersede nor consume each other,
  and the per-address issuance throttle keeps a separate bucket per origin.
  A null origin scopes to legacy (pre-1.4.0) tokens only. In-flight tokens
  issued before an upgrade carry no origin and will not verify through a
  consumer that now passes one — bounded by the token TTL (15 minutes by
  default).
- `Passkeys::verifyCreation()` and `Passkeys::deletePasskey()` accept an
  optional per-call recent-auth window, so each consumer enforces its own
  policy instead of mutating the shared `recentAuthDuration` default.
- `authkit_tokens.origin` column (schema 1.2.0); existing rows keep a null
  origin.

### Deprecated
- Mutating the shared `Tokens` service properties (`magicLinkRoute`,
  `registrationRoute`, `tokenTtl`, `otpDigits`, `otpMaxAttempts`,
  `perEmailLimit`, `perEmailWindow`) and `Passkeys::$recentAuthDuration` from
  consuming plugins. They remain as defaults, but with more than one consumer
  installed the last writer silently wins — pass per-issuance options and
  per-call windows instead.

## 1.3.0 - 2026-07-16

### Added
- The `SESSION_REVOKED` audit event's `scope` vocabulary gains `frontchannel`
  (IdP-initiated front-channel logout) and `global` (Global Token Revocation)
  alongside the existing `single` / `others` / `backchannel`, so emitters can
  attribute a session kill to the channel that actually caused it. Scope values
  remain additive vocabulary: sinks ignore values they don't recognize.

### Changed
- `Passkeys::deletePasskey()` now returns a bool reporting whether a credential
  was actually removed. Core's delete is a silent no-op for an unknown UID, so
  the wrapper performs the presence check; consumers use the return value to
  keep audit trails factual instead of recording deletions that never happened.
  Existing callers that ignore the return value are unaffected.

## 1.2.0 - 2026-07-13

> This release folds in the never-tagged 1.1.0 work (registration tokens), so
> it is the direct successor to 1.0.1.

### Added
- Registration tokens — a third passwordless credential type (`register`) for
  an address that has no account yet. `Tokens::issueRegistration()` emails an
  unguessable, single-use, TTL'd link and mints no user row (the email lives in
  the token payload); `Tokens::consumeRegistration()` burns the token and
  returns it, proving mailbox possession without creating or resolving a user —
  the consuming plugin owns the account decision. Registration is the inverse of
  a login issuance: it proceeds only for an unknown or **pending** address (a
  pending account re-proves mailbox possession so it can finish activating) and
  refuses (silently, timing-equalized) an address that already maps to an
  active, suspended, or locked account, so a unified sign-in/sign-up endpoint
  stays enumeration-safe across both branches.
- `auth_kit_register` editable system message backing the registration email,
  and an overridable `Tokens::$registrationRoute` for the verify URL.
- Audit-event contract — the neutral cooperation seam for authentication audit
  logging, mirroring the `passwords` registry. Emitters (Warden, Warp) describe
  an auth fact with the frozen `AuthEvent` value object (event-name constants
  for the login, passkey, registration, session, and SCIM vocabularies; two
  outcome constants; readonly `userId`, `name`, `outcome`, `emitter`, `details`,
  `actorId`) and hand it to `AuthKit::$plugin->audit->record()`. Any provider
  plugin (e.g. Password Policy) registers an `AuditSinkInterface` via
  `Audit::EVENT_REGISTER_AUDIT_SINKS`; the service fans each event out to every
  sink, wrapping each in its own try/catch so a failing sink can never block an
  auth flow or the sinks after it. With no sink registered, recording is a cheap
  no-op. The `AuthEvent` shape is frozen at 1.2.0 (a change is a major bump); new
  event-name constants are additive minors, and sinks ignore names they don't
  recognize. `details` is scalar-only and carries no PII — enforced at
  construction.

### Changed
- `authkit_tokens.userId` is now nullable, so a registration token can be issued
  before its user exists. The change is a backward-compatible constraint
  loosening (a delta migration drops and re-adds the foreign key, which still
  enforces referential integrity for every non-null value); the plugin schema
  version is bumped to 1.1.0.

### Security
- `Tokens::issueRegistration()` validates the address format and refuses a
  malformed one through the same equalized path a taken address takes, so a bad
  address is timing-indistinguishable from an existing account.
- Passwordless login tokens are no longer honored for a **locked** account.
  `getStatus()` folds a lock into "active", so `consumeMagicLink()` /
  `consumeOtp()` re-checked only for an active status and would have logged a
  locked account straight in off a stale token. The consume path now checks the
  lock explicitly and fails closed (the token is still burned), mirroring the
  suspended path.

## 1.0.1 - 2026-07-11

### Changed
- Requires Craft CMS 5.10.0 or later: the passkey wrappers serialize creation
  options through core's WebAuthn serializer, which is only public as of
  5.10.0.

### Security
- Every failure branch of `consumeOtp()` now pays the constant-time equalizer,
  including a stale token and a wrong code submitted against a live token,
  closing an account-enumeration timing oracle.

### Fixed
- Magic-link verify URLs no longer use Craft's reserved `token` query param
  (which core rejects with a 400 before the consuming controller is reached);
  the raw token now travels as `mlToken` (`Tokens::TOKEN_PARAM`).
- OTP token hashes are scoped to their user (SHA-256 over the user UID plus
  the code), so two users holding the same code no longer collide on the
  unique `tokenHash` index with an uncaught `IntegrityException` on issue.
  Magic-link hashing is unchanged.
- The `passkeys` service now enforces the recent-auth gate its docblock
  promised: `verifyCreation()` and `deletePasskey()` throw a
  `yii\web\ForbiddenHttpException` when the session has not authenticated
  within the recent-auth window.
- `PasswordValidationResult` is a plain final value class with readonly
  `isValid` and `errors` properties, so `errors` can no longer shadow the
  `getErrors()` validation API it inherited as a `craft\base\Model` subclass.

## 1.0.0 - 2026-06-17

> Initial release.

### Added
- Unified passwordless token core (`tokens` service) — issue and consume
  hashed, single-use, TTL'd credentials for both magic links and email OTP
  codes, backed by a single `authkit_tokens` table. Magic links carry a
  32-byte secret; OTP codes are short, attempt-capped, and superseded on
  re-issue.
- Enumeration- and timing-safe issuance: unknown and ineligible addresses take
  the same code path (constant-time equalizer + per-address throttle) and never
  reveal whether an account exists.
- Passkey wrappers (`passkeys` service) over core's WebAuthn machinery —
  creation options, verify-creation, list, delete — for front-end users.
- Recent-auth gate — the passwordless replacement for elevated sessions;
  stamps on login and is checked by consumers via `passkeys` service helpers.
- `PasswordValidatorInterface` + a validator registry (`passwords` service) —
  the neutral cooperation seam for password policy and breach checks. Graceful
  no-op when no validator is registered.
- Shared front-end `authkit-webauthn.js`, a `craft.authKit` Twig variable, and
  default `auth_kit_magic_link` / `auth_kit_otp` system messages.
- Expired tokens are pruned automatically on Craft's garbage-collection pass
  (`craft\services\Gc::EVENT_RUN`), so consuming plugins get cleanup for free.
