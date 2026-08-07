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

use Craft;

/**
 * Device turns a raw user-agent string into a coarse, human-friendly label like
 * "Chrome on macOS" — the name a member sees against each active session in the
 * shared session registry.
 *
 * This is display-only labelling, deliberately shallow: a handful of substring
 * checks over the common browser and OS families, no third-party parser, and no
 * attempt at recognition. It is emphatically NOT fingerprinting — two different
 * phones can share a label, and that is fine. The label never influences
 * authorization; it only helps a person tell "my laptop" from "my phone" in a
 * list.
 *
 * Order matters in both passes: several user-agents embed older tokens for
 * compatibility (Edge and Opera both carry `Chrome`; Chrome carries `Safari`),
 * so the more specific family is tested first and wins.
 *
 * @author CraftPulse
 * @since 1.10.0
 */
abstract class Device
{
    // Const Properties
    // =========================================================================

    /**
     * @var string A conventional desktop or laptop computer.
     *
     * @since 1.10.0
     */
    public const TYPE_DESKTOP = 'desktop';

    /**
     * @var string A phone or other handheld device.
     *
     * @since 1.10.0
     */
    public const TYPE_MOBILE = 'mobile';

    /**
     * @var string A tablet.
     *
     * @since 1.10.0
     */
    public const TYPE_TABLET = 'tablet';

    /**
     * @var string An unrecognised or missing device.
     *
     * @since 1.10.0
     */
    public const TYPE_UNKNOWN = 'unknown';

    // Public Methods
    // =========================================================================

    /**
     * Returns a coarse "Browser on OS" label for a user-agent string, or a
     * generic "Unknown device" when nothing recognisable is found (or the
     * string is missing entirely).
     *
     * @param string|null $userAgent the raw user-agent, or null when none was captured
     * @return string a display label — "Chrome on macOS", "Safari", "Windows", or "Unknown device"
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    public static function label(?string $userAgent): string
    {
        $unknown = Craft::t('auth-kit', 'Unknown device');

        if ($userAgent === null || trim($userAgent) === '') {
            return $unknown;
        }

        $browser = self::_browser($userAgent);
        $os = self::_os($userAgent);

        if ($browser !== null && $os !== null) {
            return Craft::t('auth-kit', '{browser} on {os}', ['browser' => $browser, 'os' => $os]);
        }

        return $browser ?? $os ?? $unknown;
    }

    /**
     * Returns the coarse device class for a user-agent — one of the `TYPE_*`
     * constants — so a session card can show a device-type icon. Deliberately
     * shallow substring matching, never fingerprinting: a tablet with no obvious
     * marker may read as a desktop, and that is fine.
     *
     * @param string|null $userAgent the raw user-agent, or null when none was captured
     * @return string one of [[TYPE_DESKTOP]], [[TYPE_MOBILE]], [[TYPE_TABLET]], or [[TYPE_UNKNOWN]]
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    public static function type(?string $userAgent): string
    {
        if ($userAgent === null || trim($userAgent) === '') {
            return self::TYPE_UNKNOWN;
        }

        return match (true) {
            str_contains($userAgent, 'iPad'), str_contains($userAgent, 'Tablet') => self::TYPE_TABLET,
            str_contains($userAgent, 'Android') && !str_contains($userAgent, 'Mobile') => self::TYPE_TABLET,
            str_contains($userAgent, 'iPhone'),
            str_contains($userAgent, 'iPod'),
            str_contains($userAgent, 'Mobile'),
            str_contains($userAgent, 'Android') => self::TYPE_MOBILE,
            str_contains($userAgent, 'Windows'),
            str_contains($userAgent, 'Macintosh'),
            str_contains($userAgent, 'Mac OS X'),
            str_contains($userAgent, 'CrOS'),
            str_contains($userAgent, 'Linux') => self::TYPE_DESKTOP,
            default => self::TYPE_UNKNOWN,
        };
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the coarse browser family for a user-agent, or null when none of
     * the known families match.
     *
     * @param string $userAgent the raw user-agent
     * @return string|null the browser name, or null
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    private static function _browser(string $userAgent): ?string
    {
        return match (true) {
            str_contains($userAgent, 'Edg') => 'Edge',
            str_contains($userAgent, 'OPR/'), str_contains($userAgent, 'Opera') => 'Opera',
            str_contains($userAgent, 'Firefox') => 'Firefox',
            str_contains($userAgent, 'Chrome') => 'Chrome',
            str_contains($userAgent, 'Safari') => 'Safari',
            default => null,
        };
    }

    /**
     * Returns the coarse operating-system family for a user-agent, or null when
     * none of the known families match.
     *
     * @param string $userAgent the raw user-agent
     * @return string|null the OS name, or null
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    private static function _os(string $userAgent): ?string
    {
        return match (true) {
            str_contains($userAgent, 'iPhone'), str_contains($userAgent, 'iPad'), str_contains($userAgent, 'iPod') => 'iOS',
            str_contains($userAgent, 'Android') => 'Android',
            str_contains($userAgent, 'Windows') => 'Windows',
            str_contains($userAgent, 'Mac OS X'), str_contains($userAgent, 'Macintosh') => 'macOS',
            str_contains($userAgent, 'CrOS') => 'ChromeOS',
            str_contains($userAgent, 'Linux') => 'Linux',
            default => null,
        };
    }
}
