<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\db;

/**
 * Table defines the database table names owned by Auth Kit.
 *
 * Every table here is shared: one row store per concern, whichever consumer
 * (Warden, Warp, a third-party plugin) happens to write it. That is the point
 * of the module — two consumers running parallel registries would each detect
 * the same new location and each send their own alert.
 *
 * @author CraftPulse
 * @since 1.0.0
 */
abstract class Table
{
    // Const Properties
    // =========================================================================

    /**
     * @since 1.10.0
     */
    public const LOCATIONS = '{{%authkit_locations}}';

    /**
     * @since 1.10.0
     */
    public const SESSIONS = '{{%authkit_sessions}}';

    /**
     * @since 1.0.0
     */
    public const TOKENS = '{{%authkit_tokens}}';
}
