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
 * Adds the `origin` column to the tokens table — the issuing consumer's label
 * (e.g. a plugin handle). Tokens are consumed strictly within their origin,
 * so two consuming plugins sharing the store can no longer honor each other's
 * credentials; existing rows keep a null origin (legacy scope).
 *
 * @author Michael Thomas
 * @since 1.4.0
 */
class m260716_000001_AddTokenOrigin extends Migration
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function safeUp(): bool
    {
        if (!$this->db->columnExists(Table::TOKENS, 'origin')) {
            $this->addColumn(Table::TOKENS, 'origin', $this->string(32)->after('type'));
        }

        return true;
    }

    /**
     * @inheritdoc
     */
    public function safeDown(): bool
    {
        if ($this->db->columnExists(Table::TOKENS, 'origin')) {
            $this->dropColumn(Table::TOKENS, 'origin');
        }

        return true;
    }
}
