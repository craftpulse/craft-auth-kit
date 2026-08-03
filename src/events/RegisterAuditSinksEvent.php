<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\events;

use craftpulse\authkit\audit\AuditSinkInterface;
use yii\base\Event;

/**
 * RegisterAuditSinksEvent collects the audit sinks a provider plugin contributes
 * to the Auth Kit `audit` registry.
 *
 * @author CraftPulse
 * @since 1.2.0
 */
class RegisterAuditSinksEvent extends Event
{
    // Public Properties
    // =========================================================================

    /**
     * @var AuditSinkInterface[] The registered audit sinks.
     *
     * @since 1.2.0
     */
    public array $sinks = [];
}
