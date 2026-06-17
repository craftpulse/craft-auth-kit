# Auth Kit

Foundational authentication primitives for Craft CMS 5 — passwordless tokens
(magic links + email OTP), passkey wrappers, a recent-auth gate, and a
password-validator contract. The shared base for the CraftPulse security
ecosystem.

Auth Kit is **primitives + contracts**. It ships no routes, controllers, or
UX — consuming plugins ([Warden](https://github.com/craftpulse/craft-warden),
Warp, a Password Policy adapter) own those and call into Auth Kit's services.
It is a free, foundational plugin rather than a bare library because the token
store needs a table and migrations: a single installed plugin owns the
`authkit_*` schema once, so consumers never collide on it.

## Requirements

- Craft CMS 5.3.0 or later
- PHP 8.2 or later

## Installation

```sh
composer require craftpulse/craft-auth-kit
./craft plugin/install auth-kit
```

Most of the time you won't install Auth Kit directly — it is pulled in as a
Composer dependency of the plugin that uses it.

## What it provides

### Token core — `AuthKit::$plugin->tokens`

Issue and consume hashed, single-use, TTL'd passwordless credentials. The raw
secret is never persisted (only its SHA-256 hash); consumption burns the token
atomically; issuance is enumeration- and timing-safe.

```php
use craftpulse\authkit\AuthKit;

$tokens = AuthKit::$plugin->tokens;

// Magic links — a 32-byte secret emailed as a verify URL, no attempt cap.
$tokens->issueMagicLink($email, $returnUrl);     // bool — respond identically regardless
$user = $tokens->consumeMagicLink($rawToken);    // ?User

// Email OTP — short numeric code, attempt-capped, superseded on re-issue.
$tokens->issueOtp($email);                        // bool
$user = $tokens->consumeOtp($email, $code);       // ?User

// Maintenance — prune expired rows (safe on a schedule).
$tokens->purgeExpiredTokens();                    // int rows deleted
```

Tunable as service properties (no settings model — set on the component, e.g.
via `config/app.php`): `tokenTtl` (default 900s), `otpDigits` (6),
`otpMaxAttempts` (5), `perEmailLimit` (5), `perEmailWindow` (300s), and
`magicLinkRoute` — the site route your plugin registers for the verify URL
(Auth Kit imposes no URLs).

> [!IMPORTANT]
> `issueMagicLink()` / `issueOtp()` return whether a credential was actually
> sent, but any public-facing caller **must respond identically** whether or
> not the address exists — that is what keeps the endpoint enumeration-safe.
> Per-IP rate limiting belongs on your controller (core's `RateLimiter`); the
> per-address throttle here covers every channel including programmatic use.

### Passkeys & recent-auth — `AuthKit::$plugin->passkeys`

Thin wrappers over core's WebAuthn machinery for front-end users, plus the
recent-auth gate (the passwordless replacement for elevated sessions; stamped
automatically on login).

```php
$passkeys = AuthKit::$plugin->passkeys;

$passkeys->getCreationOptions($user);                  // string (JSON) for the browser
$passkeys->verifyCreation($credentials, $name);        // bool
$passkeys->getPasskeys($user);                         // array
$passkeys->hasPasskeys($user);                         // bool
$passkeys->deletePasskey($user, $uid);

$passkeys->hasRecentAuth($within);                     // bool — gate sensitive actions
$passkeys->stampRecentAuth();
```

### Password validation contract — `AuthKit::$plugin->passwords`

The neutral cooperation seam for password strength and breach checks. Plugins
cooperate through this contract and a registry — **never** by sniffing each
other with `isPluginInstalled()`.

```php
$result = AuthKit::$plugin->passwords->validate($password, $user);

if (!$result->isValid) {
    // surface $result errors
}
```

A provider (e.g. Password Policy) registers a validator implementing
`craftpulse\authkit\passwords\PasswordValidatorInterface`:

```php
use craftpulse\authkit\services\Passwords;
use craftpulse\authkit\events\RegisterPasswordValidatorsEvent;
use yii\base\Event;

Event::on(
    Passwords::class,
    Passwords::EVENT_REGISTER_PASSWORD_VALIDATORS,
    function(RegisterPasswordValidatorsEvent $event) {
        $event->validators[] = new MyPolicyValidator();
    }
);
```

If no validator is registered, `validate()` is a graceful no-op (valid). The
interface is deliberately tiny and stable — treat any change to it as a major
version bump.

### Front end

A `craft.authKit` Twig variable exposes `hasPasskeys`, `passkeys`, and
`webauthnJsUrl` for templates, and Auth Kit publishes a shared
`authkit-webauthn.js` browser client. Default `auth_kit_magic_link` and
`auth_kit_otp` system messages ship out of the box; consumers override them.

## Events

| Service | Event | Fired |
|---|---|---|
| `tokens` | `EVENT_AFTER_ISSUE_TOKEN` | after a token is issued |
| `tokens` | `EVENT_BEFORE_CONSUME_TOKEN` | before consume (cancelable — refuses login, leaves the token unburned) |
| `tokens` | `EVENT_AFTER_CONSUME_TOKEN` | after consume, user resolved |
| `passwords` | `EVENT_REGISTER_PASSWORD_VALIDATORS` | to register password validators |

## Consumers

| Plugin | Uses Auth Kit for |
|---|---|
| **Warden** | Lite passwordless: magic links, passkeys, recent-auth |
| **Warp** (planned) | the whole passwordless product surface |
| **Password Policy** (planned adapter) | *provides* a `PasswordValidatorInterface` adapter |

## License

[MIT](LICENSE) — © CraftPulse
