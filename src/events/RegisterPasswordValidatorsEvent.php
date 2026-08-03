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

use craftpulse\authkit\passwords\PasswordValidatorInterface;
use yii\base\Event;

/**
 * RegisterPasswordValidatorsEvent collects the password validators a provider
 * plugin contributes to the Auth Kit `passwords` registry.
 *
 * @author CraftPulse
 * @since 1.0.0
 */
class RegisterPasswordValidatorsEvent extends Event
{
    // Public Properties
    // =========================================================================

    /**
     * @var PasswordValidatorInterface[] The registered password validators.
     *
     * @since 1.0.0
     */
    public array $validators = [];
}
