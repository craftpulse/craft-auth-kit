# Audit

The `audit` service is a neutral cooperation seam for authentication audit logging. An emitter describes an authentication fact as an `AuthEvent` and hands it to `record()`; a provider registers a sink that persists or forwards it. Neither side knows the other exists.

As with the password contract, plugins cooperate through the registry and never by sniffing each other with `isPluginInstalled()`. An emitter calls `record()` unconditionally. On an install where nothing is registered, it is a cheap no-op.

## Recording an event

```php
use craftpulse\authkit\AuthKit;
use craftpulse\authkit\audit\AuthEvent;

AuthKit::getInstance()->getAudit()->record(new AuthEvent(
    name: AuthEvent::LOGIN_SSO,
    emitter: 'my-plugin',
    userId: $user->id,
    details: ['provider' => $providerHandle],
));
```

`record()` fans the event out to every registered sink in registration order, wrapping each one in its own try/catch. A sink that throws is logged and skipped, so it can neither block the auth flow nor stop the sinks after it.

## The event

`AuthEvent` is a final value object with six readonly properties. Its shape is frozen at 1.2.0: the properties and the constructor signature are the contract, and any change to them is a major version bump. New event-name constants are additive and ship in minor releases.

| Property | Description |
|---|---|
| `name` | The neutral event name, usually one of the class constants below. |
| `emitter` | The emitting plugin's handle, for example `warden` or `warp`. |
| `outcome` | Either `AuthEvent::OUTCOME_SUCCESS` or `AuthEvent::OUTCOME_FAILURE`. Defaults to success. |
| `userId` | The subject user's ID, or null when no user is resolved. |
| `details` | Scalar-only, non-PII context for the event. Defaults to empty. |
| `actorId` | The acting admin or system user, or null when the subject acted on their own behalf. |

### Event names

| Constant | Description |
|---|---|
| `LOGIN_MAGIC_LINK` | A magic-link login succeeded. |
| `LOGIN_NEW_LOCATION` | A login arrived from a country and city the user had never signed in from before. `details` carries `country`, and `city` when one was resolved. Emitted once per user and place across the whole install, however many consumers are watching. See [Sessions and locations](sessions.md). |
| `LOGIN_OTP` | A one-time-code login succeeded. |
| `LOGIN_PASSKEY` | A passkey login succeeded. |
| `LOGIN_SSO` | A single-sign-on login succeeded. `details` carries the identity provider handle under `provider`. |
| `PASSKEY_ENROLLED` | A passkey was enrolled. |
| `PASSKEY_DELETED` | A passkey was deleted. |
| `REGISTRATION_FULFILLED` | A passwordless registration was fulfilled. |
| `SCIM_PROVISIONED` | A user was provisioned. `details` carries the `trigger`, either `scim` or `jit`. |
| `SCIM_DEPROVISIONED` | A user was deprovisioned. `details` carries the `trigger`, either `scim` or `jit`. |
| `SESSION_REVOKED` | A session was revoked. `details` carries the `scope`. |

`SESSION_REVOKED` scopes are `single` and `others` for user-initiated device revocations, `backchannel` and `frontchannel` for identity-provider-initiated logout channels, and `global` for a Global Token Revocation request. Paired with `OUTCOME_FAILURE`, the event records a revocation that was refused before any session was touched, for example a back-channel logout token that failed signature validation. No session died, and the attempt itself is the audit fact.

### The three rules

1. **`details` is scalar-only and carries no PII.** No emails, no raw IPs, no raw user agents. Only `bool`, `int`, `float`, and `string` values are accepted, and a non-scalar value throws at construction. A downstream sink may have an allowlist that strips unknown keys, but future sinks will not, so the payload stays clean at the source. `outcome` is validated the same way: anything but the two constants throws.
2. **Sinks ignore unknown names silently.** `name` is deliberately not validated against the constants. Auth Kit adds names in minor releases, so a sink will eventually receive a name newer than the vocabulary it was written against, and it must not error on one.
3. **Emitters never edition-gate emission.** Emit unconditionally. What is worth keeping is the sink's decision, not the emitter's.

## Registering a sink

A provider plugin ships a class implementing `craftpulse\authkit\audit\AuditSinkInterface` and registers it from its own `init()`:

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
        $event->sinks[] = new MyAuditSink();
    }
);
```

`AuditSinkInterface` is one method, `handle(AuthEvent $event): void`. Two rules bind every implementation: ignore names you do not recognize, and fail softly. The service wraps each sink in its own try/catch, but treat that as a backstop rather than an error-handling strategy, and log and return rather than throw.

## Reading and replacing the registry

```php
use craftpulse\authkit\AuthKit;

$audit = AuthKit::getInstance()->getAudit();

// Get the registered sinks, assembling them from the event on first access.
$sinks = $audit->getSinks();

// Replace the registry outright.
$audit->setSinks([]);
```

The registry is assembled lazily on first access, so register in `init()`. `setSinks()` is for tests and explicit wiring, and replaces whatever another provider contributed.

## The bridge seam

`Audit::EVENT_AFTER_RECORD` is a second, independent way to observe a recorded event, added in 1.5.0.

Where the sink registry is Auth Kit's own cooperation contract, with a provider registering an `AuditSinkInterface` directly on the service, `EVENT_AFTER_RECORD` lets a downstream observer relay the event elsewhere without registering as a sink at all. It exists chiefly so [Audit Kit](https://github.com/craftpulse/craft-audit-kit)'s bridge can relay every recorded `AuthEvent` onto its own neutral audit bus. See [Events](events.md) for the listener sample.

Three things to know about it:

1. **It is independent of the sink registry.** The sink fan-out and this event are two separate statements in `record()`, with no shared guard between them. Muting the sinks with `setSinks([])` does not mute this event, and attaching a listener here does not add a sink. Neither surface supersedes the other, and neither is deprecated.
2. **It fires on every `record()` call, gated only by whether a listener is attached.** With no listener it is a cheap no-op, exactly like an empty sink registry.
3. **It carries the same frozen `AuthEvent`** on a small read-only wrapper, `AuditRecordEvent::$event`. A listener cannot mutate the fan-out that has already happened.

A provider plugin can use either seam, or both, for entirely different downstream stores. Prefer the sink registry when you are the store; prefer the event when you are relaying somewhere else.

## Testing

A suite that stubs out audit recording has to neutralize both surfaces. Clearing the sink registry has no effect on an `EVENT_AFTER_RECORD` listener attached elsewhere, for example by a co-installed Audit Kit. Detach that listener too, or the test will still relay a real event onto Audit Kit's bus.
