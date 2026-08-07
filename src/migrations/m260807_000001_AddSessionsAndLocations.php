<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft CMS.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\migrations;

use craft\db\Migration;
use craftpulse\authkit\db\Table;

/**
 * Adds the shared device registry (`authkit_sessions`) and the shared
 * new-location history (`authkit_locations`).
 *
 * Both were previously a consuming plugin's private tables, which meant two
 * plugins on one install kept two registries and each sent its own alert about
 * the same sign-in. One table each, owned here, is what makes that impossible.
 *
 * All the schema work lives in [[Install]], the canonical idempotent owner; this
 * dated migration only gives it a slot on the `module:auth-kit` track for an
 * install that already ran the earlier ones. On a fresh install `Install` has
 * already created both tables and this is a no-op.
 *
 * @author CraftPulse
 * @since 1.10.0
 */
class m260807_000001_AddSessionsAndLocations extends Migration
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function safeUp(): bool
    {
        (new Install())->safeUp();

        return true;
    }

    /**
     * @inheritdoc
     */
    public function safeDown(): bool
    {
        $this->dropTableIfExists(Table::SESSIONS);
        $this->dropTableIfExists(Table::LOCATIONS);

        return true;
    }
}
