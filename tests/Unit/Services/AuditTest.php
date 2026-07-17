<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
 *
 * Tests for the audit service: the sink registry no-op default, lazy assembly
 * from the registration event, ordered fan-out through record(), and the
 * guarantee that a throwing sink is isolated — it neither bubbles nor blocks the
 * sinks after it. Also covers the AuthEvent value class's frozen shape:
 * outcome/scalar-details enforcement and immutability.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craftpulse\authkit\audit\AuditSinkInterface;
use craftpulse\authkit\audit\AuthEvent;
use craftpulse\authkit\events\AuditRecordEvent;
use craftpulse\authkit\events\RegisterAuditSinksEvent;
use craftpulse\authkit\services\Audit;

/**
 * Returns a sink that appends the event names it handled to the given log array
 * (by reference), or throws if $throw is set.
 */
function recordingSink(array &$log, ?string $throw = null): AuditSinkInterface
{
    return new class($log, $throw) implements AuditSinkInterface {
        /** @param string[] $log */
        public function __construct(private array &$log, private ?string $throw)
        {
        }

        public function handle(AuthEvent $event): void
        {
            $this->log[] = $event->name;

            if ($this->throw !== null) {
                throw new RuntimeException($this->throw);
            }
        }
    };
}

it('records nothing and does not error when no sinks are registered', function() {
    $service = new Audit();
    $service->setSinks([]);

    $event = new AuthEvent(AuthEvent::LOGIN_SSO, 'warden');

    // A zero-sink record() is a cheap no-op — it must not throw.
    $service->record($event);

    expect($service->getSinks())->toBe([]);
});

it('dispatches an event to every registered sink, in registration order', function() {
    $log = [];
    $service = new Audit();
    $service->setSinks([
        recordingSink($log),
        recordingSink($log),
    ]);

    $service->record(new AuthEvent(AuthEvent::LOGIN_PASSKEY, 'warp'));

    expect($log)->toBe([AuthEvent::LOGIN_PASSKEY, AuthEvent::LOGIN_PASSKEY]);
});

it('isolates a throwing sink: it neither bubbles nor blocks the sinks after it', function() {
    $log = [];
    $service = new Audit();
    $service->setSinks([
        recordingSink($log),
        recordingSink($log, throw: 'sink exploded'),
        recordingSink($log),
    ]);

    // record() must not bubble the sink's exception...
    $service->record(new AuthEvent(AuthEvent::SESSION_REVOKED, 'warden', details: ['scope' => 'backchannel']));

    // ...and every sink, including the one after the thrower, must have run.
    expect($log)->toBe([
        AuthEvent::SESSION_REVOKED,
        AuthEvent::SESSION_REVOKED,
        AuthEvent::SESSION_REVOKED,
    ]);
});

it('fires EVENT_AFTER_RECORD once, carrying the recorded event, after the sink fan-out', function() {
    $order = [];
    $service = new Audit();

    $log = [];
    $sink = recordingSink($log);
    $service->setSinks([$sink]);

    $received = null;
    $service->on(Audit::EVENT_AFTER_RECORD, function(AuditRecordEvent $event) use (&$order, &$received): void {
        $order[] = 'after';
        $received = $event->event;
    });

    // Wrap the sink call order: the sink logs to $log, the after-record
    // handler logs to $order — assert the after-record handler ran last.
    $original = new AuthEvent(AuthEvent::LOGIN_OTP, 'warp', userId: 9);
    $service->record($original);

    expect($log)->toBe([AuthEvent::LOGIN_OTP])
        ->and($order)->toBe(['after'])
        ->and($received)->toBe($original);
});

it('does not fire EVENT_AFTER_RECORD when no listener is attached', function() {
    // With no listener the record() call is a cheap no-op on the bridge seam —
    // it must not throw and must still fan out to sinks.
    $log = [];
    $service = new Audit();
    $service->setSinks([recordingSink($log)]);

    $service->record(new AuthEvent(AuthEvent::LOGIN_SSO, 'warden'));

    expect($log)->toBe([AuthEvent::LOGIN_SSO]);
});

it('assembles sinks from the registration event on first use', function() {
    $log = [];
    $service = new Audit();

    $handler = function(RegisterAuditSinksEvent $event) use (&$log): void {
        $event->sinks[] = recordingSink($log);
    };
    $service->on(Audit::EVENT_REGISTER_AUDIT_SINKS, $handler);

    $service->record(new AuthEvent(AuthEvent::PASSKEY_ENROLLED, 'warp'));

    expect($log)->toBe([AuthEvent::PASSKEY_ENROLLED]);
});

it('rejects an outcome that is not one of the two outcome constants', function() {
    expect(fn() => new AuthEvent(AuthEvent::LOGIN_OTP, 'warp', outcome: 'partial'))
        ->toThrow(InvalidArgumentException::class);
});

it('accepts both success and failure outcomes', function() {
    $success = new AuthEvent(AuthEvent::LOGIN_MAGIC_LINK, 'warp', outcome: AuthEvent::OUTCOME_SUCCESS);
    $failure = new AuthEvent(AuthEvent::LOGIN_MAGIC_LINK, 'warp', outcome: AuthEvent::OUTCOME_FAILURE);

    expect($success->outcome)->toBe('success')
        ->and($failure->outcome)->toBe('failure');
});

it('defaults the outcome to success', function() {
    $event = new AuthEvent(AuthEvent::REGISTRATION_FULFILLED, 'warp');

    expect($event->outcome)->toBe(AuthEvent::OUTCOME_SUCCESS);
});

it('rejects non-scalar details, enforcing the scalar-only contract', function() {
    expect(fn() => new AuthEvent(AuthEvent::LOGIN_SSO, 'warden', details: ['provider' => ['nested' => 'array']]))
        ->toThrow(InvalidArgumentException::class);

    expect(fn() => new AuthEvent(AuthEvent::LOGIN_SSO, 'warden', details: ['object' => new stdClass()]))
        ->toThrow(InvalidArgumentException::class);
});

it('accepts scalar details of every scalar type', function() {
    $event = new AuthEvent(AuthEvent::SCIM_PROVISIONED, 'warden', details: [
        'trigger' => 'scim',
        'count' => 3,
        'ratio' => 1.5,
        'forced' => true,
    ]);

    expect($event->details)->toBe([
        'trigger' => 'scim',
        'count' => 3,
        'ratio' => 1.5,
        'forced' => true,
    ]);
});

it('does not validate the event name, tolerating names newer than the vocabulary', function() {
    // Forward compatibility: an emitter on a newer Auth Kit may send a name this
    // build has never heard of. Construction must succeed regardless.
    $event = new AuthEvent('login.future_method', 'warp');

    expect($event->name)->toBe('login.future_method');
});

it('keeps the event a plain immutable value class', function() {
    $event = new AuthEvent(
        AuthEvent::SCIM_DEPROVISIONED,
        'warden',
        outcome: AuthEvent::OUTCOME_SUCCESS,
        userId: 42,
        details: ['trigger' => 'scim'],
        actorId: 7,
    );

    expect($event)->not->toBeInstanceOf(yii\base\Model::class)
        ->and($event->userId)->toBe(42)
        ->and($event->actorId)->toBe(7)
        ->and($event->emitter)->toBe('warden');

    // readonly properties cannot be reassigned after construction.
    expect(fn() => $event->outcome = AuthEvent::OUTCOME_FAILURE)
        ->toThrow(Error::class);
});
