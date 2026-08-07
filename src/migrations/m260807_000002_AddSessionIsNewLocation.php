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
 * Adds the `isNewLocation` column to the shared device registry.
 *
 * "This account just signed in from a place it has never been" is decided once,
 * inside [[\craftpulse\authkit\services\Sessions::record()]], and now persisted
 * with the session it describes — so a consumer badges and filters on a stored
 * fact instead of recomputing the same answer against its own history.
 *
 * Rows written before this migration keep a null, which reads as "never
 * assessed" rather than the false claim that the registry checked and found the
 * place familiar. See [[Install::_addColumns()]] for the full reasoning.
 *
 * All the schema work lives in [[Install]], the canonical idempotent owner; this
 * dated migration only gives it a slot on the `module:auth-kit` track for an
 * install that already ran the earlier ones.
 *
 * @author CraftPulse
 * @since 1.11.0
 */
class m260807_000002_AddSessionIsNewLocation extends Migration
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function safeUp(): bool
    {
        (new Install(['db' => $this->db]))->safeUp();

        return true;
    }

    /**
     * @inheritdoc
     */
    public function safeDown(): bool
    {
        if ($this->db->columnExists(Table::SESSIONS, 'isNewLocation')) {
            $this->dropColumn(Table::SESSIONS, 'isNewLocation');
        }

        return true;
    }
}
