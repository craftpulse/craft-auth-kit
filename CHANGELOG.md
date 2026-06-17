# Release Notes for Auth Kit

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
