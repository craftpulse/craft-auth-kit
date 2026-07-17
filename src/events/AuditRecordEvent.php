<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\events;

use craftpulse\authkit\audit\AuthEvent;
use yii\base\Event;

/**
 * AuditRecordEvent carries the {@see AuthEvent} that
 * [[\craftpulse\authkit\services\Audit::record()]] just fanned out to its
 * registered sinks. It fires from
 * [[\craftpulse\authkit\services\Audit::EVENT_AFTER_RECORD]] once, after the
 * synchronous sink fan-out, so a downstream observer (chiefly the Audit Kit
 * bridge) can relay the event onto the neutral audit bus without registering as
 * an Auth Kit sink itself.
 *
 * Additive and read-only: the event exposes the already-constructed value
 * object and never lets a listener mutate the fan-out. Treat the property as the
 * contract.
 *
 * @author Michael Thomas
 * @since 1.5.0
 */
class AuditRecordEvent extends Event
{
    // Public Properties
    // =========================================================================

    /**
     * @var AuthEvent The event that was just recorded.
     *
     * @since 1.5.0
     */
    public AuthEvent $event;
}
