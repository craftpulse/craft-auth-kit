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
 * m260711_000001_MakeTokenUserIdNullable loosens `authkit_tokens.userId` to be
 * nullable, so a registration token can be issued before any user row exists.
 *
 * A registration credential proves mailbox possession for an address that does
 * not yet map to an account — the email lives in the token payload and the
 * `userId` stays null until the consuming plugin creates the user at verify
 * time. This keeps issuance from minting pending user rows on anonymous email
 * submission (an enumeration and garbage-row vector).
 *
 * The alter is a constraint loosening, so it is backward-compatible: existing
 * rows all carry a non-null `userId` and stay valid. The foreign key is dropped
 * for the alter and re-added afterwards; a foreign key on a nullable column
 * still enforces referential integrity for every non-null value and simply
 * skips the check for nulls, so registration tokens carry no dangling
 * reference.
 *
 * @author Michael Thomas
 * @since 1.1.0
 */
class m260711_000001_MakeTokenUserIdNullable extends Migration
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function safeUp(): bool
    {
        // The foreign key must be dropped before the column it references can be
        // altered; it is re-added once the column is nullable.
        $this->dropForeignKeyIfExists(Table::TOKENS, ['userId']);

        if ($this->db->getIsMysql()) {
            $this->alterColumn(Table::TOKENS, 'userId', $this->integer());
        } else {
            // Postgres: altering a column from a ColumnSchemaBuilder does not
            // reliably emit the NOT NULL change, so drop the constraint directly.
            $this->execute(sprintf('ALTER TABLE %s ALTER COLUMN [[userId]] DROP NOT NULL', Table::TOKENS));
        }

        $this->addForeignKey(null, Table::TOKENS, ['userId'], CraftTable::USERS, ['id'], 'CASCADE', null);

        return true;
    }

    /**
     * @inheritdoc
     */
    public function safeDown(): bool
    {
        // Re-tightening fails if any registration token (null userId) still
        // exists; that is expected — the column cannot go back to NOT NULL while
        // user-less credentials are outstanding.
        $this->dropForeignKeyIfExists(Table::TOKENS, ['userId']);

        if ($this->db->getIsMysql()) {
            $this->alterColumn(Table::TOKENS, 'userId', $this->integer()->notNull());
        } else {
            $this->execute(sprintf('ALTER TABLE %s ALTER COLUMN [[userId]] SET NOT NULL', Table::TOKENS));
        }

        $this->addForeignKey(null, Table::TOKENS, ['userId'], CraftTable::USERS, ['id'], 'CASCADE', null);

        return true;
    }
}
