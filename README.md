# Auth Kit

Foundational authentication primitives for Craft CMS 5: passwordless tokens
(magic links + email OTP), passkey wrappers, a recent-auth gate, a
password-validator contract, and an audit-event contract. The shared base for
the CraftPulse security ecosystem.

Auth Kit is **primitives + contracts**. It ships no routes, controllers, or
UX. Consuming plugins ([Warden](https://github.com/craftpulse/craft-warden),
Warp, a Password Policy adapter) own those and call into Auth Kit's services.

Since 1.7.0 Auth Kit is a **library-shipped Yii module**, following the
`verbb/auth` model: it never appears in Craft's installed-plugins list, has no
install or enable state of its own, and cannot be disabled. Consuming plugins
require the package and register the module at runtime. Auth Kit still owns
the `authkit_*` schema exactly once, through its own migration track
(`module:auth-kit`), so consumers never collide on it however many of them
share an install.

## Requirements

- Craft CMS 5.10.0 or later (the passkey wrappers use core's WebAuthn
  serializer, which is only public as of 5.10.0)
- PHP 8.2 or later

## Installation

Auth Kit is not installed on its own and there is no `plugin/install` step. A
consuming plugin requires the package:

```sh
composer require craftpulse/craft-auth-kit
```

and wires it up in three places, described next.

## Wiring Auth Kit into a consuming plugin

### 1. Register the module

Call the idempotent `AuthKit::register()` from your plugin's `init()`:

```php
use craftpulse\authkit\AuthKit;

public function init(): void
{
    parent::init();

    AuthKit::register();

    // ...
}
```

The first call creates the module, sets it on the application under the
`auth-kit` module ID, and attaches Auth Kit's event wiring (expired-token
garbage collection, recent-auth stamping on login, the editable system
messages, and the `craft.authKit` variable). Every later call returns the
existing instance, so any number of consumers (Warp and Warden on the same
install, for example) can each call it safely.

`AuthKit::getInstance()` and the `AuthKit::$plugin` shorthand keep working
from any context and lazily register the module if no plugin has yet.

### 2. Apply Auth Kit's migrations from your install migration

Auth Kit owns its migrations and runs them through its own migration manager
on the `module:auth-kit` track. Your plugin's `Install` migration applies them
with one line:

```php
public function safeUp(): bool
{
    \craftpulse\authkit\AuthKit::getInstance()->getMigrator()->up();

    // ... your own schema ...

    return true;
}
```

Applied migrations are recorded on the module track, so a second consumer's
install finds nothing left to do.

Auth Kit has no plugin schema version for Craft to watch, so a release that
adds a migration is not picked up on its own. When you bump your Auth Kit
requirement to a release whose changelog lists a new migration, ship a dated
migration of your own containing the same one line. This is the `verbb/auth`
model, and it keeps schema changes on your plugin's own upgrade path rather
than on an implicit one:

```php
public function safeUp(): bool
{
    \craftpulse\authkit\AuthKit::getInstance()->getMigrator()->up();

    return true;
}
```

### 3. Upgrading from the plugin era (Auth Kit 1.6.x and earlier)

Installs that carried Auth Kit as a plugin need a one-time adoption when the
consumer moves to 1.7.0+. Ship a normal dated migration containing:

```php
public function safeUp(): bool
{
    \craftpulse\authkit\migrations\Adoption::adoptFromPlugin();

    return true;
}
```

`Adoption::adoptFromPlugin()` marks the plugin era's already-applied Auth Kit
migrations as applied on the module track, removes the leftover `auth-kit` row
from the `plugins` table and the `plugins.auth-kit` project config entry (with
project config events muted, and without ever touching the `authkit_*`
tables), then runs the module migrator's `up()` to apply anything still
pending. Every step is idempotent: the call is safe to re-run, safe when
several consumers each ship it, and safe on an install that never had the
plugin, where it simply applies the schema fresh. Ship this migration in the
same consumer release that bumps the Auth Kit requirement to `^1.7.0`, so the
stale plugin registration is cleaned up on the very `craft up` that follows
the composer update.

## What it provides

### Token core: `AuthKit::$plugin->tokens`

Issue and consume hashed, single-use, TTL'd passwordless credentials. The raw
secret is never persisted (only its SHA-256 hash); consumption burns the token
atomically; issuance is enumeration- and timing-safe.

```php
use craftpulse\authkit\AuthKit;

$tokens = AuthKit::$plugin->tokens;

// Magic links: a 32-byte secret emailed as a verify URL, no attempt cap.
$tokens->issueMagicLink($email, $returnUrl);     // bool, respond identically regardless
$user = $tokens->consumeMagicLink($rawToken);    // ?User

// Email OTP: short numeric code, attempt-capped, superseded on re-issue.
$tokens->issueOtp($email);                        // bool
$user = $tokens->consumeOtp($email, $code);       // ?User

// Guest OTP: short numeric code bound to an ARBITRARY mailbox, not a user.
// Proves inbox control for any valid email (member or external); the recipient
// never becomes a user, is never logged in, and gets no session.
$tokens->issueGuestOtp($email, 'my-plugin');        // void, never reveals if sent
$proved = $tokens->consumeGuestOtp($email, $code, 'my-plugin'); // bool

// Registration: a 32-byte secret for an address with no account yet.
// Mints no user row; the email lives in the token payload until verify time.
$tokens->issueRegistration($email, $returnUrl);   // bool, unknown address only
$token = $tokens->consumeRegistration($rawToken); // ?Token, payload carries the email

// Maintenance: prune expired rows (safe on a schedule).
$tokens->purgeExpiredTokens();                    // int rows deleted
```

Registration is the inverse of a login issuance: `issueRegistration()` proceeds
only for an address with no account yet, and refuses (silently, timing-equalized)
any address that already maps to a user of any status. The two branches a unified
sign-in/sign-up endpoint dispatches between (existing address to `issueMagicLink()`,
unknown address to `issueRegistration()`) stay indistinguishable by timing.
`consumeRegistration()` proves only mailbox possession and returns the burned
token; the consuming plugin owns the account decision (create, activate, log in)
from the payload's email.

The guest OTP is the user-less sibling of `issueOtp()`: it issues to any
syntactically valid email whether or not it maps to a Craft user, and
`consumeGuestOtp()` returns a plain bool for whether the code proved control of
the mailbox. Nothing is logged in and no session is created, because a guest
verification is not an authentication, so it emits no `AuthEvent`, and the raw
email is never stored (the token carries only the SHA-256 of the lowercased
address). Attribution is the consuming plugin's audit story. Its `origin` is a
required argument (not an option), since a guest code only makes sense scoped to
the consumer that issued it.

Tunable as service properties (no settings model, so set them on the component
via `config/app.php`, declaring the module and only the components you are
overriding, since Auth Kit fills in the rest):

```php
'modules' => [
    'auth-kit' => [
        'class' => \craftpulse\authkit\AuthKit::class,
        'components' => [
            'tokens' => ['tokenTtl' => 600],
        ],
    ],
],
```

The tunables are `tokenTtl` (default 900s), `otpDigits` (6),
`otpMaxAttempts` (5), `perEmailLimit` (5), `perEmailWindow` (300s),
`magicLinkRoute`, and `registrationRoute`, the site routes your plugin
registers for the verify URLs (Auth Kit imposes no URLs).

> [!IMPORTANT]
> `issueMagicLink()` / `issueOtp()` / `issueRegistration()` return whether a
> credential was actually sent, but any public-facing caller **must respond
> identically** whether or not the address exists. That is what keeps the
> endpoint enumeration-safe. Per-IP rate limiting belongs on your controller
> (core's `RateLimiter`); the per-address throttle here covers every channel
> including programmatic use.

### Passkeys & recent-auth: `AuthKit::$plugin->passkeys`

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

$passkeys->hasRecentAuth($within);                     // bool, gate sensitive actions
$passkeys->stampRecentAuth();
```

> [!IMPORTANT]
> The credential-changing operations enforce the gate themselves:
> `verifyCreation()` and `deletePasskey()` throw a
> `yii\web\ForbiddenHttpException` when the session has not authenticated
> within the recent-auth window. Check `hasRecentAuth()` in your controller
> first for a friendly response. The gate authenticates the session, not the
> target: always pass the authenticated user's own element, never a user
> resolved from request input.

### Password validation contract: `AuthKit::$plugin->passwords`

The neutral cooperation seam for password strength and breach checks. Plugins
cooperate through this contract and a registry, **never** by sniffing each
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
interface is deliberately tiny and stable, so treat any change to it as a major
version bump.

### Audit events: `AuthKit::$plugin->audit`

The neutral cooperation seam for authentication audit logging. Emitters describe
an auth fact with the `AuthEvent` value object and hand it to `record()`;
provider plugins register sinks that persist or forward it. Plugins cooperate
through this contract and a registry, **never** by sniffing each other with
`isPluginInstalled()`.

An emitter (Warden, Warp) records an event:

```php
use craftpulse\authkit\audit\AuthEvent;

AuthKit::$plugin->audit->record(new AuthEvent(
    name: AuthEvent::LOGIN_SSO,
    emitter: 'warden',
    userId: $user->id,
    details: ['provider' => $providerHandle],   // scalar-only, no PII
));
```

A provider (e.g. Password Policy) registers a sink implementing
`craftpulse\authkit\audit\AuditSinkInterface`:

```php
use craftpulse\authkit\audit\AuditSinkInterface;
use craftpulse\authkit\audit\AuthEvent;
use craftpulse\authkit\events\RegisterAuditSinksEvent;
use craftpulse\authkit\services\Audit;
use yii\base\Event;

Event::on(
    Audit::class,
    Audit::EVENT_REGISTER_AUDIT_SINKS,
    function(RegisterAuditSinksEvent $event) {
        $event->sinks[] = new class implements AuditSinkInterface {
            public function handle(AuthEvent $event): void
            {
                // Persist or forward. Ignore names you don't recognize.
            }
        };
    }
);
```

`record()` fans the event out to every registered sink in order, wrapping each
in its own try/catch: a sink that throws is logged and skipped, never blocking
the auth flow nor the sinks after it. With no sink registered, `record()` is a
cheap no-op.

The contract has three rules:

1. **`details` is scalar-only and carries no PII.** No emails, raw IPs, or raw
   user agents. Only `bool`, `int`, `float`, and `string` values are accepted; a
   non-scalar value throws at construction. (`outcome` is likewise validated: it
   must be `OUTCOME_SUCCESS` or `OUTCOME_FAILURE`.)
2. **Sinks ignore unknown event names silently.** Auth Kit adds names in minor
   releases, so a sink may receive a name newer than the vocabulary it was
   written against, and it must not error on one.
3. **Emitters never edition-gate emission.** Emit unconditionally; the sink side
   decides what to keep.

The `AuthEvent` shape is frozen at 1.2.0, so treat any change to its properties or
constructor as a major version bump. New event-name constants, by contrast, are
additive and ship in minors.

### Audit Kit bridge: `Audit::EVENT_AFTER_RECORD`

A second, independent seam on the same `record()` call, added in 1.5.0. Where
the sink registry above is Auth Kit's own cooperation contract (a provider
registers a `AuditSinkInterface` directly on Auth Kit's `Audit` component),
`EVENT_AFTER_RECORD` lets a downstream observer relay the event elsewhere
without ever registering as a sink at all. It exists chiefly so
[Audit Kit](https://github.com/craftpulse/craft-audit-kit)'s bridge can relay
every recorded `AuthEvent` onto its own neutral audit bus.

`record()` fires it once, after the sink fan-out has run to completion:

```php
use craftpulse\authkit\events\AuditRecordEvent;
use craftpulse\authkit\services\Audit;
use yii\base\Event;

Event::on(
    Audit::class,
    Audit::EVENT_AFTER_RECORD,
    function(AuditRecordEvent $event) {
        // $event->event is the same AuthEvent record() was called with.
    }
);
```

Three things to know about this seam:

1. **It is independent of the sink registry.** The sink loop and the
   `EVENT_AFTER_RECORD` trigger are two separate, unconditional statements in
   `record()` with no shared guard. Muting the sinks (`setSinks([])`) does
   **not** mute this event, and attaching a listener here does not add a sink.
   Neither surface supersedes the other, and neither is deprecated.
2. **It fires unconditionally, gated only by whether a listener is attached.**
   With no listener it is a cheap no-op, exactly like an empty sink registry.
3. **It carries the same frozen `AuthEvent` on a small, read-only wrapper**
   (`AuditRecordEvent::$event`). It never lets a listener mutate the fan-out
   that already happened.

A provider plugin can use either seam, or both, for entirely different
downstream stores. Password Policy, for example, registers a sink (surface
one) to land events on its own hash-chained audit log, while Audit Kit's
bridge listens on `EVENT_AFTER_RECORD` (surface two) to feed its own bus. Both
run on every `record()` call, independently of each other.

**Testing note:** a suite that stubs out audit recording must neutralize
*both* surfaces. Clearing the sink registry (`Audit::setSinks([])`) has no
effect on an `EVENT_AFTER_RECORD` listener already attached elsewhere (for
example, by a co-installed Audit Kit); detach that listener too, or the test
will still relay a real event onto Audit Kit's bus.

### Front end

A `craft.authKit` Twig variable exposes `hasPasskeys`, `passkeys`, and
`webauthnJsUrl` for templates, and Auth Kit publishes a shared
`authkit-webauthn.js` browser client. Default `auth_kit_magic_link`,
`auth_kit_otp`, and `auth_kit_register` system messages ship out of the box;
consumers override them.

## Events

| Service | Event | Fired |
|---|---|---|
| `tokens` | `EVENT_AFTER_ISSUE_TOKEN` | after a token is issued |
| `tokens` | `EVENT_BEFORE_CONSUME_TOKEN` | before consume (cancelable: refuses login, leaves the token unburned) |
| `tokens` | `EVENT_AFTER_CONSUME_TOKEN` | after consume, user resolved |
| `passwords` | `EVENT_REGISTER_PASSWORD_VALIDATORS` | to register password validators |
| `audit` | `EVENT_REGISTER_AUDIT_SINKS` | to register audit sinks |
| `audit` | `EVENT_AFTER_RECORD` | after every `record()` call, independently of the sink registry (the Audit Kit bridge point) |

## Consumers

| Plugin | Uses Auth Kit for |
|---|---|
| **Warden** | Lite passwordless: magic links, passkeys, recent-auth |
| **Warrant** | pinned to `~1.6.0` until its own module retrofit |
| **Warp** (planned) | the whole passwordless product surface |
| **Password Policy** (planned adapter) | *provides* a `PasswordValidatorInterface` adapter |

## License

[MIT](LICENSE), © CraftPulse
