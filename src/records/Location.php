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
 * Location record maps the `authkit_locations` table — the shared history of
 * coarse places a user has successfully signed in from, and the ledger of which
 * of those they have already been alerted about.
 *
 * One row per (user, country, city). It is deliberately not a log: repeat
 * sign-ins from a known place touch [[$dateUpdated]] and nothing else, so the
 * table stays proportional to how much a member travels rather than to how
 * often they sign in, and it needs no retention window of its own.
 *
 * [[$dateAlerted]] is what stops two consuming plugins from each emailing the
 * same member about the same trip: the first alert stamps it, and every other
 * consumer's alert for the same place inside the dedupe window is refused.
 *
 * @property int $id
 * @property int $userId
 * @property string $country
 * @property string|null $city
 * @property string|null $dateAlerted
 * @property string $dateCreated
 * @property string $dateUpdated
 * @property string $uid
 *
 * @author CraftPulse
 * @since 1.10.0
 */
class Location extends ActiveRecord
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public static function tableName(): string
    {
        return Table::LOCATIONS;
    }
}
