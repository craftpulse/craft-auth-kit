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
     */
    public function safeUp(): bool
    {
        if (!$this->db->columnExists(Table::TOKENS, 'subject')) {
            $this->addColumn(Table::TOKENS, 'subject', $this->char(64)->after('origin'));
            $this->createIndex(null, Table::TOKENS, ['subject']);
        }

        return true;
    }

    /**
     * @inheritdoc
     */
    public function safeDown(): bool
    {
        if ($this->db->columnExists(Table::TOKENS, 'subject')) {
            $this->dropColumn(Table::TOKENS, 'subject');
        }

        return true;
    }
}
