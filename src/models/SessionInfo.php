<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\models;

use craft\base\Model;
use craftpulse\authkit\helpers\Device;
use DateTime;

/**
 * SessionInfo is one row a session-management screen renders: a single active
 * Craft session, resolved for display. It is assembled by
 * [[\craftpulse\authkit\services\Sessions::getSessionsForUser()]] by joining
 * the user's live rows in core's `{{%sessions}}` table against the shared
 * device registry, never persisted itself.
 *
 * The [[uid]] is the registry row's UID, the handle a front end posts back to
 * revoke this one session — the raw token is never exposed. A session core knows
 * about but the registry does not (created before the registry existed, or by a
 * path no consumer captures) still appears, labelled as an unknown device and
 * with a null [[uid]]; those are revocable only through "sign out everywhere
 * else", since there is no per-row handle to target.
 *
 * @author CraftPulse
 * @since 1.10.0
 */
class SessionInfo extends Model
{
    // Public Properties
    // =========================================================================

    /**
     * @var string|null The city the session was registered from, or null when no
     * geo database is present or the session predates geo capture.
     *
     * @since 1.10.0
     */
    public ?string $city = null;

    /**
     * @var string A coarse, human-friendly device label like "Chrome on macOS",
     * derived from the captured user-agent by
     * [[\craftpulse\authkit\helpers\Device::label()]]. "Unknown device" when the
     * user-agent is missing or the session predates the registry.
     *
     * @since 1.10.0
     */
    public string $deviceLabel = '';

    /**
     * @var string The coarse device class — one of the
     * [[\craftpulse\authkit\helpers\Device]] `TYPE_*` constants — driving the
     * device-type icon on each session card.
     *
     * @since 1.10.0
     */
    public string $deviceType = Device::TYPE_UNKNOWN;

    /**
     * @var bool Whether this is the session making the current request — the one
     * a "this device" badge marks and that "sign out everywhere else" spares.
     *
     * @since 1.10.0
     */
    public bool $isCurrent = false;

    /**
     * @var bool|null Whether the session was registered from a place the user
     * had never been seen at before — the "signed in from somewhere new" badge.
     * Null when the question was never asked: a session that predates the
     * registry, or one recorded before Auth Kit 1.11.0 began storing the answer.
     * Null is not `false`; treat it as unknown rather than as a place the
     * registry checked and found familiar.
     *
     * @since 1.11.0
     */
    public ?bool $isNewLocation = null;

    /**
     * @var string|null The IP captured when the session was registered, or null
     * for a session that predates the registry.
     *
     * @since 1.10.0
     */
    public ?string $ip = null;

    /**
     * @var DateTime|null When the session was last seen, taken from core's own
     * `{{%sessions}}.dateUpdated` — core touches it as the session is used, so
     * it reflects genuine activity rather than the registry's bookkeeping.
     *
     * @since 1.10.0
     */
    public ?DateTime $lastSeen = null;

    /**
     * @var string|null The registry row's UID, the handle a front end posts to
     * revoke this session. Null for a session with no registry row — revocable
     * only through "sign out everywhere else".
     *
     * @since 1.10.0
     */
    public ?string $uid = null;
}
