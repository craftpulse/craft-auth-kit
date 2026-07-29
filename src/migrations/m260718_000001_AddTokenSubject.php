<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
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
 * Adds the `subject` column to the tokens table — the queryable lookup key for
 * an email-bound guest OTP, which has no `userId`.
 *
 * A user-bound OTP is located at consume time by its `userId` so a wrong code
 * still finds the row to charge an attempt against; a guest OTP proves control
 * of an arbitrary mailbox and has no user, so it needs its own discriminator.
 * `subject` holds the sha256 of the lowercased email (never the raw address —
 * attribution is the consuming plugin's audit story), which lets the newest
 * live guest code for an email be found without the code being submitted, so
 * the attempt cap mirrors the user-bound path exactly. Existing rows and every
 * other token type keep a null `subject`.
 *
 * @author Michael Thomas
 * @since 1.6.0
 */
class m260718_000001_AddTokenSubject extends Migration
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * The column and the index are checked independently, and the index goes
     * through [[craft\db\Migration::createIndexIfMissing()]] rather than a bare
     * `createIndex()`. Both halves matter, for opposite reasons.
     *
     * Sharing the column's `columnExists()` guard (as this originally did) made
     * the index unreachable once the column existed, so a run that added the
     * column and then died before indexing it skipped the index forever on
     * every retry — a silently missing index behind the guest OTP subject
     * lookup, with no error to point at it.
     *
     * Hoisting the call out of that guard makes it reachable on every
     * invocation, which is exactly where a bare `createIndex()` becomes
     * dangerous: it names the index randomly and neither MySQL nor Postgres
     * rejects a second, functionally identical index under a different name, so
     * a replay (a lost migration history row, a manual `migrate/up`, a harness
     * that provisions the schema directly) would pile up duplicates with no
     * error until the table crossed MySQL's 64-key-per-table ceiling and every
     * subsequent install failed outright. `createIndexIfMissing()` is what
     * makes reachability safe.
     *
     * Together, each step is a true no-op when its own change is already in
     * place, and self-healing when only one of the two is.
     */
    public function safeUp(): bool
    {
        if (!$this->db->columnExists(Table::TOKENS, 'subject')) {
            $this->addColumn(Table::TOKENS, 'subject', $this->char(64)->after('origin'));
        }

        $this->createIndexIfMissing(Table::TOKENS, ['subject']);

        return true;
    }

    /**
     * @inheritdoc
     *
     * The index is dropped explicitly rather than left to the column drop's
     * cascade, so the down step names what it removes instead of relying on
     * per-driver behavior, and so an interrupted `safeUp()` that indexed
     * without adding the column still gets cleaned up.
     */
    public function safeDown(): bool
    {
        $this->dropIndexIfExists(Table::TOKENS, ['subject']);

        if ($this->db->columnExists(Table::TOKENS, 'subject')) {
            $this->dropColumn(Table::TOKENS, 'subject');
        }

        return true;
    }
}
