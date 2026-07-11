<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\services;

use Craft;
use craftpulse\authkit\audit\AuditSinkInterface;
use craftpulse\authkit\audit\AuthEvent;
use craftpulse\authkit\events\RegisterAuditSinksEvent;
use Throwable;
use yii\base\Component;

/**
 * Audit holds a registry of [[AuditSinkInterface]] implementations and fans an
 * [[AuthEvent]] out to every registered sink.
 *
 * This is the cooperation seam described in PLAN §3, and it mirrors the shipped
 * [[Passwords]] registry exactly: an emitter (Warden, Warp) calls [[record()]]
 * on any auth flow, and any provider plugin (e.g. Password Policy) contributes a
 * sink via the [[EVENT_REGISTER_AUDIT_SINKS]] event or [[setSinks()]]. The sinks
 * are assembled lazily on first use, just like [[Passwords::getValidators()]].
 *
 * Recording is synchronous and defensive: each sink is invoked inside its own
 * try/catch, so a failing sink is isolated — it can neither block the auth flow
 * nor prevent the remaining sinks from running. With no sinks registered
 * [[record()]] is a cheap no-op.
 *
 * An instance of the service is available via `AuthKit::$plugin->getAudit()`.
 *
 * @author Michael Thomas
 * @since 1.2.0
 */
class Audit extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * @event RegisterAuditSinksEvent The event that is triggered when the sink
     * registry is first assembled, letting provider plugins contribute their own
     * [[AuditSinkInterface]] implementations.
     * @since 1.2.0
     */
    public const EVENT_REGISTER_AUDIT_SINKS = 'registerAuditSinks';

    // Private Properties
    // =========================================================================

    /**
     * @var AuditSinkInterface[]|null The resolved sinks, lazily assembled from
     * the registration event on first use.
     *
     * @since 1.2.0
     */
    private ?array $_sinks = null;

    // Public Methods
    // =========================================================================

    /**
     * Returns the registered audit sinks, assembling them from the registration
     * event on first access.
     *
     * @return AuditSinkInterface[]
     *
     * @author Michael Thomas
     * @since 1.2.0
     */
    public function getSinks(): array
    {
        if ($this->_sinks === null) {
            $event = new RegisterAuditSinksEvent();
            $this->trigger(self::EVENT_REGISTER_AUDIT_SINKS, $event);
            $this->_sinks = $event->sinks;
        }

        return $this->_sinks;
    }

    /**
     * Records an authentication event by dispatching it to every registered
     * sink, in registration order. Each sink is wrapped in its own try/catch: a
     * sink that throws is logged and skipped, never blocking the auth flow nor
     * the sinks after it. With no sinks registered this is a no-op.
     *
     * @param AuthEvent $event the event to record
     *
     * @author Michael Thomas
     * @since 1.2.0
     */
    public function record(AuthEvent $event): void
    {
        foreach ($this->getSinks() as $sink) {
            try {
                $sink->handle($event);
            } catch (Throwable $e) {
                Craft::error(
                    sprintf(
                        'Audit sink %s threw while handling a "%s" event from "%s": %s',
                        $sink::class,
                        $event->name,
                        $event->emitter,
                        $e->getMessage(),
                    ),
                    __METHOD__,
                );
            }
        }
    }

    /**
     * Replaces the registered sinks. Primarily for tests and explicit wiring;
     * runtime registration goes through the event.
     *
     * @param AuditSinkInterface[] $sinks the sinks to register
     *
     * @author Michael Thomas
     * @since 1.2.0
     */
    public function setSinks(array $sinks): void
    {
        $this->_sinks = array_values($sinks);
    }
}
