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

/**
 * Ip coarsens a client address before it is stored. An IPv4 address has its
 * final octet zeroed (`203.0.113.45` becomes `203.0.113.0`); an IPv6 address
 * keeps only its /48 routing prefix (`2001:db8:abcd:12::1` becomes
 * `2001:db8:abcd::`) — the same truncation widths the major analytics vendors
 * use for IP anonymization.
 *
 * The result still places the address in a network coarse enough to cover many
 * households, so it no longer singles out one connection, while remaining
 * useful as a "roughly where" display value. Geo lookups are unaffected by
 * design: [[\craftpulse\authkit\services\Geo::lookup()]] runs on the full
 * address first, and only the stored copy is anonymized.
 *
 * Auth Kit's own writers anonymize by default; a consumer that wants the
 * sharper forensic value of a full address opts out per call.
 *
 * @author CraftPulse
 * @since 1.10.0
 */
abstract class Ip
{
    // Const Properties
    // =========================================================================

    /**
     * @var int How many leading bytes of a packed IPv6 address survive
     * anonymization — 6 bytes is the /48 routing prefix, matching the common
     * anonymization convention of zeroing the final 80 bits.
     *
     * @since 1.10.0
     */
    private const IPV6_PREFIX_BYTES = 6;

    // Public Methods
    // =========================================================================

    /**
     * Anonymizes an IP address by zeroing its host-identifying tail.
     *
     * Fails closed: a missing address stays null, and an address that cannot
     * be parsed as IPv4 or IPv6 returns null rather than being stored raw — a
     * malformed value is more likely header junk than an address worth keeping.
     *
     * @param string|null $ip the address to anonymize, or null when none was captured
     * @return string|null the anonymized address, or null
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    public static function anonymize(?string $ip): ?string
    {
        if ($ip === null || $ip === '') {
            return null;
        }

        $packed = @inet_pton($ip);

        if ($packed === false) {
            return null;
        }

        if (strlen($packed) === 4) {
            $packed[3] = "\x00";
        } else {
            $packed = substr($packed, 0, self::IPV6_PREFIX_BYTES)
                . str_repeat("\x00", 16 - self::IPV6_PREFIX_BYTES);
        }

        $anonymized = inet_ntop($packed);

        return $anonymized !== false ? $anonymized : null;
    }
}
