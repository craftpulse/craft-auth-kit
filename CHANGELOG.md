# Release Notes for Auth Kit

## 1.10.0 - 2026-08-07

- Added `craftpulse\authkit\services\Sessions`, a shared session registry that records a row for every sign-in regardless of channel, so consuming plugins no longer each keep their own.
- Added `craftpulse\authkit\services\Geo`, which resolves a city and country from an IP address against a local MaxMind database, and `craftpulse\authkit\helpers\Ip` and `craftpulse\authkit\helpers\Device` alongside it.
- Added `craftpulse\authkit\services\Locations`, which decides whether a sign-in comes from a place the account has not been seen at before, and claims that decision so two consuming plugins on one install send a single alert rather than one each.
- Added the `auth-kit/geo/refresh` console command, which downloads and installs the geolocation database.
- Added `craftpulse\authkit\audit\AuthEvent::LOGIN_NEW_LOCATION` and the `authkit_new_location` system message.
- Added the `authkit_sessions` and `authkit_locations` tables.
- Session capture is not wired automatically. A consuming plugin records sign-ins itself and passes its own IP anonymization preference, so adopting this release does not change what an existing install stores.
- The geolocation database is MaxMind GeoLite2, used under the GeoLite2 End User License Agreement. Sites must credit MaxMind and refresh the database at least every 30 days, replacing the copy they hold. Location resolution is skipped entirely when no database is installed.

## 1.9.0 - 2026-08-07

- Added `craftpulse\authkit\audit\AuthEvent::USER_PROVISIONED`, `craftpulse\authkit\audit\AuthEvent::USER_DEPROVISIONED`, and `craftpulse\authkit\audit\AuthEvent::USER_RESTORED`, channel-neutral event names for account lifecycle changes that do not arrive through SCIM. Each carries the originating channel in its `details.trigger` value.

## 1.8.0 - 2026-08-04

- The magic-link, one-time code, guest code, and registration emails now state exactly how long their credential lasts ("It expires in 15 minutes and can be used only once") instead of saying it expires shortly.
- Added the `expiresIn` variable to all four emails, the issuance's own lifetime formatted for reading, so a rewritten body can state the expiry too. An install that has already edited a body keeps its copy and can add the variable under Utilities, System Messages.
- Added `craftpulse\authkit\helpers\Duration::human()`, which formats a lifetime in seconds as the phrase the emails use, so a consuming plugin can state the same lifetime in its own front-end copy with the same wording.
- Documented the three levers an install has over the four emails: editing the copy in the control panel, translating the defaults through the `auth-kit` translation category, and styling them with Craft's HTML email template setting. It also covers which language an email renders in and what an edited message stops following.
- Corrected the control-panel location of the system messages screen in the documentation: it is under Utilities, then System Messages, not under the email settings.

## 1.7.4 - 2026-08-03

- Documented the boundary on `craftpulse\authkit\migrations\Adoption::adoptFromPlugin()`'s project config removal: where Craft has turned automatic YAML writing off because external changes are pending, the removal reaches the stored config only and the project config YAML keeps the entry until those changes are applied.

## 1.7.3 - 2026-08-03

- Fixed a bug where `craftpulse\authkit\migrations\Adoption::adoptFromPlugin()` could leave the `plugins.auth-kit` project config entry behind in the external YAML config, where the next external apply treats it as a plugin that still needs installing and restores the registration the adoption had just shed.
- Fixed an error that occurred when `craftpulse\authkit\migrations\Adoption::adoptFromPlugin()` ran on an install with `allowAdminChanges` set to `false`, where removing the plugin-era project config entry threw a `yii\base\NotSupportedException` and failed the consuming plugin's upgrade migration.

## 1.7.2 - 2026-08-03

- Corrected the `@since` annotations on the registration token API, which named a never-tagged 1.1.0 rather than the 1.2.0 it shipped in.

## 1.7.1 - 2026-08-03

- Added a documentation set under `docs/`, covering requirements, installation and consumer setup, the plugin-era upgrade path, and a feature tour of the token core, passkeys, password validation, audit events, template variables, and events.
- Corrected the documented registration-token behaviour: a token is issuable for an address belonging to a pending account, so its holder can complete signup, and is refused for an account in any other state.
- Documented the per-call options accepted by every issuance, the `$origin` argument on every consume, `craftpulse\authkit\services\Tokens::TOKEN_PARAM`, and that expired-token purging is already wired to Craft's garbage collection.

## 1.7.0 - 2026-08-02

### Changed
- Auth Kit is now a library-shipped Yii module instead of a Craft plugin,
  following the `verbb/auth` model. The composer package type changed from
  `craft-plugin` to `library`, so the package no longer appears in Craft's
  installed-plugins list and can no longer be installed, enabled, or disabled
  on its own. Consuming plugins (Warp, Warden) register it at runtime instead.
- `AuthKit` now extends `yii\base\Module`. Consumers call the idempotent
  `AuthKit::register()` from their plugin's `init()`; the first call creates
  the module, sets it on the application under the `auth-kit` module ID, and
  attaches Auth Kit's event wiring (garbage collection, recent-auth stamping,
  system messages, the `craft.authKit` variable). Later calls, for example
  when Warp and Warden share an install, return the existing instance.
  `AuthKit::getInstance()` and `AuthKit::$plugin` keep working everywhere,
  including inside migrations, and lazily register the module when needed.
- Auth Kit keeps owning its migrations, now run through its own migration
  manager on the `module:auth-kit` track. Consumers call
  `AuthKit::getInstance()->getMigrator()->up()` from their install migration.
  The base schema gained a dated wrapper, `m260617_000000_Install`, so the
  module track can discover it; all schema logic still lives in `Install`.
- Auth Kit no longer carries a plugin `schemaVersion`, because Craft only
  watches that for installed plugins. A release that adds a migration is
  applied by the consumer shipping a dated migration with the same
  `getMigrator()->up()` line, keeping schema changes on the consumer's own
  upgrade path. This matches the `verbb/auth` model and is documented in the
  README.
- The `auth-kit` translation category and the `@craftpulse/authkit` alias are
  now registered by the module itself, since Craft only does that
  automatically for installed plugins. Every `Craft::t('auth-kit', ...)` call
  site keeps working unchanged.

### Added
- `craftpulse\authkit\migrations\Adoption`, the documented upgrade helper that
  makes a consumer's plugin-to-module migration a one-liner:
  `Adoption::adoptFromPlugin()`. It marks the plugin era's already-applied
  migrations as applied on the module track, removes the `auth-kit` row from
  the `plugins` table and the `plugins.auth-kit` project config entry with
  project config events muted, never touches Auth Kit's tables, and finishes
  with a `migrator->up()` catch-up. Every step is idempotent and the call is
  safe on installs that never had the plugin, where it simply applies the
  schema fresh.

## 1.6.2 - 2026-07-29

### Fixed
- `m260718_000001_AddTokenSubject` no longer skips the `subject` index when the
  column already exists. The index creation sat inside the column's own
  `columnExists()` guard, so a run that added the column and then died before
  indexing it could never recover: every retry saw the column, skipped the
  whole block, and left the guest OTP subject lookup permanently unindexed with
  no error to point at it. The column and the index are now checked
  independently, so each step is a no-op when its own change is in place and
  self-healing when only one of the two is.
- The `subject` index now goes through `createIndexIfMissing()` instead of a
  bare `createIndex(null, ...)`. That matters precisely because the call is no
  longer shielded by the column guard: a bare `createIndex()` names the index
  randomly, and neither MySQL nor Postgres rejects a second, functionally
  identical index under a different name, so a reachable unguarded call would
  pile up duplicates with no error until the table crossed MySQL's
  64-key-per-table ceiling and every subsequent install failed outright. This
  is the failure 1.6.1 fixed in `Install`; the guard is now on every index
  Auth Kit creates, in every migration.
- `m260711_000001_MakeTokenUserIdNullable` no longer rewrites the column and
  drops and re-adds the `userId` foreign key on a replay. The alter now runs
  only while the column is still `NOT NULL`, and the constraint is re-added
  only when `Db::findForeignKey()` finds none over `userId`, so replaying the
  migration is a true no-op instead of a needless column rebuild with a window
  where referential integrity is not enforced. The previous unconditional
  drop-then-add held at one constraint only because the drop immediately
  preceded the add, which was incidental rather than stated: a bare
  `addForeignKey(null, ...)` names the constraint randomly and duplicates are
  accepted, and `dropForeignKeyIfExists()` removes only the first constraint it
  finds over the columns. Both up and down steps are guarded.
- `m260718_000001_AddTokenSubject`'s `safeDown()` now drops the `subject` index
  explicitly instead of relying on the column drop's per-driver cascade, so the
  down step names what it removes and also cleans up after an interrupted
  `safeUp()` that indexed without adding the column.

### Notes
- A new `tests/Unit/Migrations/IdempotencyTest.php` replays all four migrations
  against an already-migrated schema and asserts the index and foreign-key
  inventory is unchanged, asserts there is exactly one index per indexed column
  set, and reconstructs the partial-application state (column present, index
  missing) to prove the recovery path. It is the regression guard that would
  have caught the reintroduction; the previous `InstallTest` covered only
  `Install`.
- Exposure for the two migrations above was narrower than for the `Install`
  case fixed in 1.6.1, and neither could accumulate duplicate keys on its own.
  Craft's `installPlugin()` runs only the `Install` migration and then records
  the numbered migrations as applied without executing them, so the plugin's
  own test harness fallback (which reaches for `installPlugin()` whenever Auth
  Kit is not registered as installed, even against a database whose tables
  already exist) replays `Install` and only `Install`, never the numbered
  migrations. The `AddTokenSubject` index call was in turn unreachable once its
  column existed, and the `MakeTokenUserIdNullable` foreign key was re-added
  only immediately after being dropped. Forcing all three numbered migrations
  to execute three times over an already-migrated schema on the released 1.6.1
  code leaves the index and foreign-key count unchanged, so the 64-key ceiling
  incidents observed in the wild trace to `Install`'s pre-1.6.1 bare calls, not
  to these. What this release removes is the remaining unguarded calls, whose
  safety rested on surrounding code rather than on the call itself.
- No `safeDown()` changed its observable outcome. `migrate/down` still reverts
  to the pre-1.6.0 schema (`origin` and `subject` dropped, `userId` back to
  `NOT NULL`, foreign key intact) and `migrate/up` still restores it exactly,
  with no change in index or foreign-key count either way. This is a patch
  release: no schema change, no `schemaVersion` bump, and nothing for an
  existing install to migrate. Upgrading runs no DDL on any install that is
  already current.
- `schemaVersion` was audited across every release tag and is correct at
  `1.3.0`. It is an independent, monotonic schema counter rather than a mirror
  of the release version, and each migration did carry its bump: `1.0.0` at
  install, `1.1.0` with `m260711_000001_MakeTokenUserIdNullable` (shipped in
  1.2.0), `1.2.0` with `m260716_000001_AddTokenOrigin` (1.4.0), and `1.3.0`
  with `m260718_000001_AddTokenSubject` (1.6.0). Every upgrade path therefore
  reports a pending database update and applies what it is missing, verified by
  upgrading a reconstructed install that stored `1.1.0` and lacked both
  columns: Craft found both migrations pending and applied them, landing
  `origin varchar(32)`, `subject char(64)`, and exactly one `subject` index.
  The property now documents this so the counter is not mistaken for the
  release version and bumped or skipped by accident.

## 1.6.1 - 2026-07-28

### Changed
- Documented `Audit::EVENT_AFTER_RECORD` (shipped in 1.5.0) in the README: a
  new "Audit Kit bridge" subsection covers what it is, when it fires, that it
  runs independently of the sink registry (muting sinks does not mute it),
  the `AuditRecordEvent` payload, and a testing note that neutralizing audit
  recording must clear both surfaces.

### Fixed
- The `Install` migration is now idempotent. `_createIndexes()` and
  `_addForeignKeys()` ran unconditionally on every `safeUp()`, unlike
  `_createTables()`'s own `tableExists()` guard, so any context that
  re-invokes the migration directly against a database that already has
  `authkit_tokens` (a standalone test harness whose plugin-install detection
  lags reality, for instance) kept adding duplicate, functionally identical
  indexes and foreign keys with no error. `createIndexIfMissing()` and a new
  `_addForeignKeyIfMissing()` guard make every call a true no-op against an
  already-provisioned table.

## 1.6.0 - 2026-07-18

### Added
- An email-bound guest OTP primitive, so a consuming plugin can prove that a
  visitor controls an arbitrary mailbox without ever creating a user, a login,
  or a session. `Tokens::issueGuestOtp($email, $origin, $options)` issues a
  short-lived code to any syntactically valid email (member or external, no
  account required) and emails it through the new editable `auth_kit_guest_otp`
  system message; `Tokens::consumeGuestOtp($email, $code, $origin)` returns a
  bool for whether the code proved control of the mailbox. The code is
  single-use, attempt-capped, and per-email+origin throttled, mirroring the
  user-bound OTP; every consume failure is timing-uniform. A guest verification
  is deliberately not an authentication: it emits no `AuthEvent`, and the raw
  email is never stored (the token carries only the sha256 of the lowercased
  address in a new `subject` column, added by the
  `m260718_000001_AddTokenSubject` migration). Attribution is the consuming
  plugin's audit story.

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
