<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\migrations;

use craft\db\Migration;
use craft\db\Table as CraftTable;
use craft\helpers\Db;
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
     *
     * Both steps are guarded so a re-invocation is a true no-op. The alter only
     * runs while the column is still `NOT NULL`, and the foreign key is only
     * re-added when the table does not already carry one over `userId`.
     *
     * This originally ran unconditionally: drop the constraint, rewrite the
     * column, re-add the constraint. That stayed at one foreign key on a replay
     * only because the drop immediately preceded the add — incidental safety,
     * not stated safety. `addForeignKey(null, ...)` names the constraint
     * randomly and neither MySQL nor Postgres rejects a second, functionally
     * identical constraint under a different name, so the moment that ordering
     * changed (or the drop stopped matching, since `dropForeignKeyIfExists()`
     * removes only the first constraint it finds over the columns) the re-add
     * would start piling up duplicates with no error, each one consuming a key
     * slot toward MySQL's 64-key-per-table ceiling. It also meant every replay
     * needlessly dropped a live referential-integrity constraint and rewrote
     * the whole column to reach a state it was already in.
     *
     * Tracking whether the constraint was dropped in this run, rather than
     * re-reading the schema after the drop, keeps the decision independent of
     * Yii's table schema cache.
     */
    public function safeUp(): bool
    {
        $hasForeignKey = Db::findForeignKey(Table::TOKENS, ['userId'], $this->db) !== null;

        if (!$this->_userIdAllowsNull()) {
            // The foreign key must be dropped before the column it references
            // can be altered; it is re-added below once the column is nullable.
            if ($hasForeignKey) {
                $this->dropForeignKeyIfExists(Table::TOKENS, ['userId']);
                $hasForeignKey = false;
            }

            if ($this->db->getIsMysql()) {
                $this->alterColumn(Table::TOKENS, 'userId', $this->integer());
            } else {
                // Postgres: altering a column from a ColumnSchemaBuilder does not
                // reliably emit the NOT NULL change, so drop the constraint directly.
                $this->execute(sprintf('ALTER TABLE %s ALTER COLUMN [[userId]] DROP NOT NULL', Table::TOKENS));
            }
        }

        if (!$hasForeignKey) {
            $this->addForeignKey(null, Table::TOKENS, ['userId'], CraftTable::USERS, ['id'], 'CASCADE', null);
        }

        return true;
    }

    /**
     * @inheritdoc
     *
     * Guarded the same way as [[safeUp()]], and for the same reason: repeating
     * the down step must not pile up duplicate foreign keys either.
     */
    public function safeDown(): bool
    {
        $hasForeignKey = Db::findForeignKey(Table::TOKENS, ['userId'], $this->db) !== null;

        if ($this->_userIdAllowsNull()) {
            // Re-tightening fails if any registration token (null userId) still
            // exists; that is expected — the column cannot go back to NOT NULL while
            // user-less credentials are outstanding.
            if ($hasForeignKey) {
                $this->dropForeignKeyIfExists(Table::TOKENS, ['userId']);
                $hasForeignKey = false;
            }

            if ($this->db->getIsMysql()) {
                $this->alterColumn(Table::TOKENS, 'userId', $this->integer()->notNull());
            } else {
                $this->execute(sprintf('ALTER TABLE %s ALTER COLUMN [[userId]] SET NOT NULL', Table::TOKENS));
            }
        }

        if (!$hasForeignKey) {
            $this->addForeignKey(null, Table::TOKENS, ['userId'], CraftTable::USERS, ['id'], 'CASCADE', null);
        }

        return true;
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns whether `authkit_tokens.userId` already accepts null.
     *
     * The schema is read with a forced refresh so the answer reflects the
     * database rather than whatever Yii cached earlier in the request; a stale
     * `NOT NULL` reading would re-run the alter (and the drop/re-add of the
     * foreign key around it) on a column that no longer needs it.
     *
     * A missing column or table reads as "already nullable" so the alter is
     * skipped rather than attempted against a schema this migration cannot
     * repair.
     *
     * @author Michael Thomas
     * @since 1.1.0
     */
    private function _userIdAllowsNull(): bool
    {
        $column = $this->db->getTableSchema(Table::TOKENS, true)?->getColumn('userId');

        return $column === null || $column->allowNull;
    }
}
