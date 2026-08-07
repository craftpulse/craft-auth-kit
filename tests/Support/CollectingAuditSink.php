<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\tests\Support;

use craftpulse\authkit\audit\AuditSinkInterface;
use craftpulse\authkit\audit\AuthEvent;

/**
 * CollectingAuditSink keeps every [[AuthEvent]] handed to it in memory, so a
 * test can assert on what an emitter recorded without a real audit-log
 * consumer installed.
 *
 * @author CraftPulse
 * @since 1.10.0
 */
class CollectingAuditSink implements AuditSinkInterface
{
    // Public Properties
    // =========================================================================

    /**
     * @var array<int, AuthEvent> Every event received, in arrival order.
     *
     * @since 1.10.0
     */
    public array $events = [];

    // Public Methods
    // =========================================================================

    /**
     * Returns the first collected event with the given name, or null.
     *
     * @param string $name the neutral event name to look for
     * @return AuthEvent|null
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    public function firstOfName(string $name): ?AuthEvent
    {
        foreach ($this->events as $event) {
            if ($event->name === $name) {
                return $event;
            }
        }

        return null;
    }

    /**
     * @inheritdoc
     */
    public function handle(AuthEvent $event): void
    {
        $this->events[] = $event;
    }
}
