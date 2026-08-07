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
 * Install creates Auth Kit's database schema. Since the module conversion
 * (1.7.0) it is applied on the `module:auth-kit` track through its dated
 * wrapper [[m260617_000000_Install]] — Craft's migration manager only
 * discovers dated file names — while this class remains the canonical,
 * idempotent schema owner. `safeDown()` is retained for completeness and
 * tests; nothing in the module lifecycle tears the schema down.
 *
 * Auth Kit owns a single unified, type-discriminated token table backing both
 * magic links and email OTP codes. The raw token never touches the database —
 * only its sha256 hash, which is what every lookup compares against. The
 * unique constraint on `tokenHash` is part of the security model and is
 * enforced at the database level, not just validation.
 *
 * It also owns the shared device registry (`authkit_sessions`) and the shared
 * new-location history (`authkit_locations`), both introduced in 1.10.0 and
 * created here for a fresh install; existing installs get them from
 * [[m260807_000001_AddSessionsAndLocations]].
 *
 * @author CraftPulse
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
        $this->dropTableIfExists(Table::SESSIONS);
        $this->dropTableIfExists(Table::LOCATIONS);
        $this->dropTableIfExists(Table::TOKENS);

        return true;
    }

    // Private Methods
    // =========================================================================

    /**
     * Adds the foreign keys tying Auth Kit's rows to Craft's users.
     *
     * Tokens are owned by their user — CASCADE so deleting a user prunes their
     * outstanding tokens. `userId` is nullable there: a registration token has
     * no user yet, and the foreign key simply skips the reference check for that
     * null.
     *
     * Registry rows are owned by their user too, and CASCADE keeps them in step
     * with core's own `{{%sessions}}` rows, which core deletes the same way when
     * a user is removed. Location-history rows CASCADE for the same reason and
     * one more: it is what answers an erasure request with no extra step.
     *
     * Guarded by [[_addForeignKeyIfMissing()]] for the same reason
     * [[_createIndexes()]] guards every `createIndex()` call: this migration's
     * `safeUp()` can run directly against a database that already carries these
     * tables and their foreign keys (see that method's docblock), and
     * `addForeignKey()` has no name-collision protection of its own to fall
     * back on.
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    private function _addForeignKeys(): void
    {
        $this->_addForeignKeyIfMissing(Table::LOCATIONS, ['userId'], CraftTable::USERS, ['id'], 'CASCADE');
        $this->_addForeignKeyIfMissing(Table::SESSIONS, ['userId'], CraftTable::USERS, ['id'], 'CASCADE');
        $this->_addForeignKeyIfMissing(Table::TOKENS, ['userId'], CraftTable::USERS, ['id'], 'CASCADE');
    }

    /**
     * Adds a foreign key only when no constraint already covers the same
     * table and columns.
     *
     * @param string $table the table the constraint is added to
     * @param array<int, string> $columns the local columns
     * @param string $refTable the referenced table
     * @param array<int, string> $refColumns the referenced columns
     * @param string $delete the `ON DELETE` behavior
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    private function _addForeignKeyIfMissing(string $table, array $columns, string $refTable, array $refColumns, string $delete): void
    {
        if (Db::findForeignKey($table, $columns, $this->db) !== null) {
            return;
        }

        $this->addForeignKey(null, $table, $columns, $refTable, $refColumns, $delete, null);
    }

    /**
     * Creates the indexes backing Auth Kit's query patterns and uniqueness
     * guarantees.
     *
     * Every call goes through [[craft\db\Migration::createIndexIfMissing()]]
     * rather than a bare `createIndex()`: this migration runs its full
     * `safeUp()` (indexes included) every time a standalone Craft install
     * — like this plugin's own test harness — discovers Auth Kit isn't yet
     * registered as installed and falls back to invoking the migration
     * directly (see `tests/Bootstrap.php`), even when `authkit_tokens` (and
     * its indexes) already exists from a prior run against the same
     * database. `createIndex()` always names the index randomly and MySQL
     * happily allows unlimited functionally-identical indexes under
     * different names, so a bare call here re-ran on every invocation
     * accumulated duplicate indexes without ever erroring, until the table
     * crossed MySQL's 64-key-per-table ceiling and every subsequent install,
     * and therefore every test, failed outright. `createIndexIfMissing()`
     * checks for an existing index over the same columns first, so
     * re-running this migration against an already-indexed table is a true
     * no-op.
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    private function _createIndexes(): void
    {
        $this->createIndexIfMissing(Table::TOKENS, ['tokenHash'], true);
        $this->createIndexIfMissing(Table::TOKENS, ['userId']);
        $this->createIndexIfMissing(Table::TOKENS, ['subject']);
        $this->createIndexIfMissing(Table::TOKENS, ['expiryDate']);
        // The registry is looked up by user (the per-user session list) and by
        // token hash (the current-session match and the prune-by-token path).
        // The hash is unique, so two consumers capturing the same login cannot
        // produce two rows.
        $this->createIndexIfMissing(Table::SESSIONS, ['tokenHash'], true);
        $this->createIndexIfMissing(Table::SESSIONS, ['userId']);
        // Location history is only ever read one user at a time, either for the
        // whole user (is there any baseline?) or for one exact place.
        $this->createIndexIfMissing(Table::LOCATIONS, ['userId', 'country', 'city']);
    }

    /**
     * Creates Auth Kit's tables, skipping any that already exist.
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    private function _createTables(): void
    {
        if (!$this->db->tableExists(Table::TOKENS)) {
            $this->createTable(Table::TOKENS, [
                'id' => $this->primaryKey(),
                // Nullable so a registration token can be issued before its
                // user exists — the email lives in the payload until verify time.
                'userId' => $this->integer(),
                'type' => $this->string()->notNull(),
                // The issuing consumer's label (e.g. a plugin handle). Tokens
                // are consumed strictly within their origin; null = legacy.
                'origin' => $this->string(32),
                // The lookup key for an email-bound guest OTP (the sha256 of the
                // lowercased email), so a user-less code can be found by its
                // subject at consume time. Null for user-bound and legacy tokens.
                'subject' => $this->char(64),
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

        if (!$this->db->tableExists(Table::SESSIONS)) {
            $this->createTable(Table::SESSIONS, [
                'id' => $this->primaryKey(),
                'userId' => $this->integer()->notNull(),
                // The sha256 of Craft's auth-session token, never the token.
                'tokenHash' => $this->char(64)->notNull(),
                'userAgent' => $this->string(255),
                'ip' => $this->string(45),
                // Coarse location captured at session registration, for the
                // member's device cards; both stay null with no geo database.
                'city' => $this->string(255),
                'country' => $this->char(2),
                'dateCreated' => $this->dateTime()->notNull(),
                'dateUpdated' => $this->dateTime()->notNull(),
                'uid' => $this->uid(),
            ]);
        }

        if (!$this->db->tableExists(Table::LOCATIONS)) {
            $this->createTable(Table::LOCATIONS, [
                'id' => $this->primaryKey(),
                'userId' => $this->integer()->notNull(),
                // ISO 3166-1 alpha-2. A row only ever exists for a resolved
                // country, so unlike the registry's copy this one is not null.
                'country' => $this->char(2)->notNull(),
                // Null when the database placed the country but not the city.
                'city' => $this->string(255),
                // When this place was last alerted about, across every consumer
                // on the install — the stamp that keeps two plugins to one email.
                'dateAlerted' => $this->dateTime(),
                'dateCreated' => $this->dateTime()->notNull(),
                'dateUpdated' => $this->dateTime()->notNull(),
                'uid' => $this->uid(),
            ]);
        }
    }
}
