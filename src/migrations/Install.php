<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\migrations;

use craft\db\Migration;
use craft\db\Table as CraftTable;
use craftpulse\authkit\db\Table;

/**
 * Install creates Auth Kit's database schema on a fresh install and tears it
 * down on uninstall.
 *
 * Auth Kit owns a single unified, type-discriminated token table backing both
 * magic links and email OTP codes. The raw token never touches the database —
 * only its sha256 hash, which is what every lookup compares against. The
 * unique constraint on `tokenHash` is part of the security model and is
 * enforced at the database level, not just validation.
 *
 * @author Michael Thomas
 * @since 1.0.0
 */
class Install extends Migration
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function safeUp(): bool
    {
        $this->_createTables();
        $this->_createIndexes();
        $this->_addForeignKeys();

        return true;
    }

    /**
     * @inheritdoc
     */
    public function safeDown(): bool
    {
        $this->dropTableIfExists(Table::TOKENS);

        return true;
    }

    // Private Methods
    // =========================================================================

    /**
     * Adds the foreign key tying Auth Kit's tokens to Craft's users.
     *
     * Tokens are owned by their user — CASCADE so deleting a user prunes their
     * outstanding tokens.
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _addForeignKeys(): void
    {
        $this->addForeignKey(null, Table::TOKENS, ['userId'], CraftTable::USERS, ['id'], 'CASCADE', null);
    }

    /**
     * Creates the indexes backing Auth Kit's query patterns and uniqueness
     * guarantees.
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _createIndexes(): void
    {
        $this->createIndex(null, Table::TOKENS, ['tokenHash'], true);
        $this->createIndex(null, Table::TOKENS, ['userId']);
        $this->createIndex(null, Table::TOKENS, ['expiryDate']);
    }

    /**
     * Creates Auth Kit's tables, skipping any that already exist.
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _createTables(): void
    {
        if (!$this->db->tableExists(Table::TOKENS)) {
            $this->createTable(Table::TOKENS, [
                'id' => $this->primaryKey(),
                'userId' => $this->integer()->notNull(),
                'type' => $this->string()->notNull(),
                'tokenHash' => $this->char(64)->notNull(),
                'expiryDate' => $this->dateTime()->notNull(),
                'dateConsumed' => $this->dateTime(),
                'attempts' => $this->integer()->notNull()->defaultValue(0),
                'maxAttempts' => $this->integer(),
                'payload' => $this->json(),
                'dateCreated' => $this->dateTime()->notNull(),
                'dateUpdated' => $this->dateTime()->notNull(),
                'uid' => $this->uid(),
            ]);
        }
    }
}
