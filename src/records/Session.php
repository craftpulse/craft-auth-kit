<?php
/**
 * Auth Kit module for Craft CMS 5.x
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
 * Session record maps the `authkit_sessions` table — the shared device registry
 * kept alongside core's `{{%sessions}}` table, which stores only a token and its
 * timestamps and so carries no device information of its own.
 *
 * Each row pins the sha256 hash of a Craft auth-session token to the device that
 * produced it (a truncated user-agent and IP, for display only). Listing joins
 * these rows back to the user's live core sessions by re-hashing each core
 * token; revocation deletes the core row via that same hash, then the registry
 * row. Only the hash is stored, never the token itself, so a registry leak
 * yields nothing usable.
 *
 * One registry serves every consumer on the install. A login is captured once —
 * the unique index on `tokenHash` makes a second consumer's capture of the same
 * session a no-op — so two plugins can wire the same capture without producing
 * two rows, two device cards, or two alerts.
 *
 * @property int $id
 * @property int $userId
 * @property string $tokenHash
 * @property string|null $userAgent
 * @property string|null $ip
 * @property string|null $city
 * @property string|null $country
 * @property string $dateCreated
 * @property string $dateUpdated
 * @property string $uid
 *
 * @author CraftPulse
 * @since 1.10.0
 */
class Session extends ActiveRecord
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public static function tableName(): string
    {
        return Table::SESSIONS;
    }
}
