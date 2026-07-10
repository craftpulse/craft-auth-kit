# Release Notes for Auth Kit

## 1.0.0 - 2026-07-10

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

### Changed
- Requires Craft CMS 5.10.0 or later: the passkey wrappers serialize creation
  options through core's WebAuthn serializer, which is only public as of
  5.10.0.

### Security
- Every failure branch of `consumeOtp()` now pays the constant-time equalizer,
  including a wrong code submitted against a live token, closing an
  account-enumeration timing oracle.

### Fixed
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
