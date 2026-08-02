# Events

Auth Kit provides a collection of events for extending its functionality. Modules and plugins can register event listeners, typically in their `init()` methods, to modify Auth Kit's behavior.

Two kinds of event live here. The token events are lifecycle events: they let you observe and, in one case, veto what the token service is doing. The registration events are how the password and audit registries are assembled, and are covered on their own pages as well.

## Token Events

### The `afterIssueToken` event

Fires after a token has been stored and its email sent, for every issuance type.

The user is null for a registration or guest issuance, since neither one targets a Craft user. Do not treat this as an authentication signal: it records that a credential was minted, not that anyone used it.

```php
use craftpulse\authkit\events\TokenEvent;
use craftpulse\authkit\services\Tokens;
use yii\base\Event;

Event::on(Tokens::class, Tokens::EVENT_AFTER_ISSUE_TOKEN, function(TokenEvent $event) {
    $token = $event->token;
    $user = $event->user;
    // ...
});
```

### The `beforeConsumeToken` event

Fires when a presented token has been found and confirmed still usable, but before it is burned. This is the veto point: setting `$event->isValid` to false refuses the login and leaves the token unburned, so it stays usable for a later, legitimate attempt.

Use it to apply a condition Auth Kit knows nothing about, for example refusing a magic link outside business hours or from an unexpected country. The user is null for a registration consume, where the token proves a mailbox rather than an identity.

```php
use craftpulse\authkit\events\TokenEvent;
use craftpulse\authkit\services\Tokens;
use yii\base\Event;

Event::on(Tokens::class, Tokens::EVENT_BEFORE_CONSUME_TOKEN, function(TokenEvent $event) {
    $token = $event->token;
    $user = $event->user;
    $event->isValid = false;
    // ...
});
```

Cancelling leaves the token spendable, which is the right default for a policy refusal and the wrong one for a suspected attack. If you are refusing because something looks hostile, burn the token yourself rather than handing the attacker another attempt.

### The `afterConsumeToken` event

Fires after the token has been burned and, for a login token, after the target account has been re-checked as active and unlocked. Reaching this event means the authentication succeeded.

The user is null for a registration consume, where the burned token in `$event->token` carries the verified address in its payload.

```php
use craftpulse\authkit\events\TokenEvent;
use craftpulse\authkit\services\Tokens;
use yii\base\Event;

Event::on(Tokens::class, Tokens::EVENT_AFTER_CONSUME_TOKEN, function(TokenEvent $event) {
    $token = $event->token;
    $user = $event->user;
    // ...
});
```

Guest codes fire no consume event at all. Proving control of a mailbox is not an authentication, and Auth Kit keeps this vocabulary for genuine ones. Attribution of a guest verification is the consuming plugin's story.

## Password Events

### The `registerPasswordValidators` event

Fires when the validator registry is first assembled, letting provider plugins contribute their own `PasswordValidatorInterface` implementations.

The registry is assembled lazily and cached, so a listener attached after something has already called `validate()` will not be picked up. Register in `init()`.

```php
use craftpulse\authkit\events\RegisterPasswordValidatorsEvent;
use craftpulse\authkit\services\Passwords;
use yii\base\Event;

Event::on(Passwords::class, Passwords::EVENT_REGISTER_PASSWORD_VALIDATORS, function(RegisterPasswordValidatorsEvent $event) {
    $validators = $event->validators;
    $event->validators[] = new MyPolicyValidator();
    // ...
});
```

See [Passwords](passwords.md) for the interface and the verdict object.

## Audit Events

### The `registerAuditSinks` event

Fires when the sink registry is first assembled, letting provider plugins contribute their own `AuditSinkInterface` implementations.

As with the validator registry, this is assembled lazily and cached. Register in `init()`.

```php
use craftpulse\authkit\events\RegisterAuditSinksEvent;
use craftpulse\authkit\services\Audit;
use yii\base\Event;

Event::on(Audit::class, Audit::EVENT_REGISTER_AUDIT_SINKS, function(RegisterAuditSinksEvent $event) {
    $sinks = $event->sinks;
    $event->sinks[] = new MyAuditSink();
    // ...
});
```

See [Audit](audit.md) for the interface and the rules a sink has to honour.

### The `afterRecord` event

Fires once on every `record()` call, after the event has been fanned out to every registered sink. It lets a downstream observer relay the event elsewhere without registering as a sink.

It is independent of the sink registry: clearing the sinks does not mute it, and listening here does not add a sink. The `AuthEvent` it carries is read-only, and a listener cannot change the fan-out that has already happened.

```php
use craftpulse\authkit\events\AuditRecordEvent;
use craftpulse\authkit\services\Audit;
use yii\base\Event;

Event::on(Audit::class, Audit::EVENT_AFTER_RECORD, function(AuditRecordEvent $event) {
    $authEvent = $event->event;
    // ...
});
```

Prefer a sink when you are the store the event should land in, because a sink gets ordering and per-sink error isolation. Prefer this event when you are relaying the event somewhere that is not yours, which is what Audit Kit's bridge does.
