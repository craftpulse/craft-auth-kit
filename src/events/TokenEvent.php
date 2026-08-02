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

use craft\elements\User;
use craft\events\CancelableEvent;
use craftpulse\authkit\models\Token;

/**
 * TokenEvent is raised around token issuance and consumption (magic links and
 * OTP codes alike). The before-consume event fires with the looked-up,
 * still-usable token and its target user — handlers may cancel via `$isValid`
 * to refuse the login before the token is burned.
 *
 * @author Michael Thomas
 * @since 1.0.0
 */
class TokenEvent extends CancelableEvent
{
    // Public Properties
    // =========================================================================

    /**
     * @var Token|null The token being issued or consumed.
     *
     * @since 1.0.0
     */
    public ?Token $token = null;

    /**
     * @var User|null The user the token authenticates.
     *
     * @since 1.0.0
     */
    public ?User $user = null;
}
