# Release Notes for Auth Kit

## 1.1.0 - Unreleased

### Added
- Registration tokens — a third passwordless credential type (`register`) for
  an address that has no account yet. `Tokens::issueRegistration()` emails an
  unguessable, single-use, TTL'd link and mints no user row (the email lives in
  the token payload); `Tokens::consumeRegistration()` burns the token and
  returns it, proving mailbox possession without creating or resolving a user —
  the consuming plugin owns the account decision. Registration is the inverse of
  a login issuance: it proceeds only for an unknown address and refuses (silently,
  timing-equalized) any existing user of any status, so a unified sign-in/sign-up
  endpoint stays enumeration-safe across both branches.
- `auth_kit_register` editable system message backing the registration email,
  and an overridable `Tokens::$registrationRoute` for the verify URL.

### Changed
- `authkit_tokens.userId` is now nullable, so a registration token can be issued
  before its user exists. The change is a backward-compatible constraint
  loosening (a delta migration drops and re-adds the foreign key, which still
  enforces referential integrity for every non-null value); the plugin schema
  version is bumped to 1.1.0.

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
