<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
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
 * @author Michael Thomas
 * @since 1.0.0
 */
abstract class Table
{
    // Const Properties
    // =========================================================================

    /**
     * @since 1.0.0
     */
    public const TOKENS = '{{%authkit_tokens}}';
}
