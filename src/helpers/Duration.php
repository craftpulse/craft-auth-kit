<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\helpers;

use craft\helpers\DateTimeHelper;

/**
 * Duration turns a credential lifetime in seconds into the phrase a recipient
 * reads — "15 minutes", "1 hour", "1 day" — so an email can state exactly how
 * long its link or code lasts instead of hedging with "shortly".
 *
 * It is a thin pass to Craft's own [[DateTimeHelper::humanDuration()]], which
 * pluralizes and translates each component through the `app` category, so the
 * phrasing follows the language the message renders in. It lives here rather
 * than inside [[\craftpulse\authkit\services\Tokens]] so that service keeps a
 * single date API (Carbon, for the expiry arithmetic), and so a consuming plugin
 * can state the same lifetime in its own front-end copy with the same wording as
 * the email.
 *
 * @author CraftPulse
 * @since 1.8.0
 */
abstract class Duration
{
    // Public Methods
    // =========================================================================

    /**
     * Formats a lifetime in seconds as a human-readable duration.
     *
     * Seconds are shown only for a lifetime shorter than a minute, so a typical
     * token TTL reads "15 minutes" rather than "15 minutes and 0 seconds".
     *
     * @param int $seconds the lifetime to format
     * @return string
     *
     * @author CraftPulse
     * @since 1.8.0
     */
    public static function human(int $seconds): string
    {
        return DateTimeHelper::humanDuration($seconds);
    }
}
