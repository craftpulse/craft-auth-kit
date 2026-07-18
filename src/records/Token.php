<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\records;

use craft\db\ActiveRecord;
use craftpulse\authkit\db\Table;

/**
 * Token record maps the `authkit_tokens` table — an issued passwordless
 * credential (a magic link, an email OTP code, or a registration link), stored
 * only as the sha256 hash of the raw token.
 *
 * The raw token never touches the database: it is delivered once (in an email
 * URL or as a code) and re-hashed on consumption. Single-use is enforced via
 * `dateConsumed`, expiry via `expiryDate`, and brute-force resistance for OTP
 * codes via `attempts`/`maxAttempts`.
 *
 * `userId` is nullable: a registration token is issued before any user row
 * exists, so it carries a null `userId` and the target email in its payload.
 * An email-bound guest OTP is user-less too — it proves control of an arbitrary
 * mailbox and carries the sha256 of the lowercased email in `subject` as its
 * lookup key (never the raw address).
 *
 * @property int $id
 * @property int|null $userId
 * @property string $type
 * @property string|null $origin
 * @property string|null $subject
 * @property string $tokenHash
 * @property string $expiryDate
 * @property string|null $dateConsumed
 * @property int $attempts
 * @property int|null $maxAttempts
 * @property mixed $payload
 * @property string $dateCreated
 * @property string $dateUpdated
 * @property string $uid
 *
 * @author Michael Thomas
 * @since 1.0.0
 */
class Token extends ActiveRecord
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public static function tableName(): string
    {
        return Table::TOKENS;
    }
}
