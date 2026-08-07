<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\services;

use Carbon\Carbon;
use Craft;
use craft\db\Query;
use craft\elements\User;
use craft\helpers\Db;
use craft\helpers\UrlHelper;
use craftpulse\authkit\audit\AuthEvent;
use craftpulse\authkit\AuthKit;
use craftpulse\authkit\db\Table;
use craftpulse\authkit\records\Location as LocationRecord;
use Throwable;
use yii\base\Component;

/**
 * Locations owns new-location awareness: the rule that decides whether a
 * sign-in came from somewhere the member has never been, the shared history
 * that rule reads by default, and the one alert that goes out when it fires.
 *
 * It exists as a shared service for one reason. Two security plugins on the
 * same install, each keeping its own login history and its own alerting, both
 * notice the same trip to Tokyo and both email the member about it. Here the
 * rule is one implementation ([[isNew()]]), the history is one table
 * (`authkit_locations`, written by [[seen()]] from the shared session
 * registry), and the alert is claimed exactly once ([[alert()]] stamps
 * `dateAlerted` and refuses every other consumer inside [[$alertWindow]]).
 *
 * A consumer that keeps a richer login log of its own — Warp's `warp_logins`,
 * for instance — hands [[isNew()]] a [[Query]] over that log instead, so it
 * keeps its own baseline semantics while still sharing the rule and the alert.
 *
 * Everything here is best-effort. A missing address, an undeliverable message,
 * or a failed write is logged and swallowed: bookkeeping about a login must
 * never disturb the login itself.
 *
 * An instance is available via `AuthKit::$plugin->getLocations()`.
 *
 * @author CraftPulse
 * @since 1.10.0
 */
class Locations extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * @var string The emitter handle recorded against an audit event when a
     * consumer names none of its own.
     *
     * @since 1.10.0
     */
    public const DEFAULT_EMITTER = 'auth-kit';

    /**
     * @var string The system-message key for Auth Kit's own new-location alert.
     * Registered in `PluginTrait::_registerSystemMessages()`. A consumer that
     * already ships its own editable copy passes its own key instead, so an
     * install's customized message is never orphaned.
     *
     * @since 1.10.0
     */
    public const MESSAGE_KEY_NEW_LOCATION = 'authkit_new_location';

    // Public Properties
    // =========================================================================

    /**
     * @var int How long, in seconds, one alert about a place suppresses every
     * later alert about the same place for the same user. This is what keeps two
     * consuming plugins from both emailing about one trip; it is deliberately far
     * longer than a request, because the second consumer's notice can arrive on a
     * later login in the same journey.
     *
     * @since 1.10.0
     */
    public int $alertWindow = 86400;

    // Public Methods
    // =========================================================================

    /**
     * Claims a new location for a user and, unless told otherwise, emails them
     * about it.
     *
     * The claim is the point: the first caller stamps `dateAlerted` on the
     * shared location row and returns true, and every other caller for the same
     * user and place inside [[$alertWindow]] returns false having done nothing.
     * So two consumers that each independently decide the location is new still
     * produce one audit fact and one email.
     *
     * The audit fact is recorded on every successful claim, including one that
     * suppresses the email — an install that has turned member alerts off still
     * wants the sign-in from a new country in its audit log.
     *
     * @param User $user the member who signed in
     * @param string|null $country the resolved ISO country, or null to do nothing
     * @param string|null $city the resolved city, or null when only a country resolved
     * @param array{emitter?: string, messageKey?: string, notify?: bool, sessionsUrl?: string} $options
     * per-call options: `emitter` the consumer's handle for the audit fact,
     * `messageKey` the system message to compose from, `notify` whether to send
     * the email at all, and `sessionsUrl` the link the copy points at
     * @return bool whether this call claimed the location
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    public function alert(User $user, ?string $country, ?string $city, array $options = []): bool
    {
        if ($country === null || $user->id === null) {
            return false;
        }

        $userId = (int)$user->id;
        $record = $this->_claim($userId, $country, $city);

        if ($record === null) {
            return false;
        }

        AuthKit::getInstance()->getAudit()->record(new AuthEvent(
            name: AuthEvent::LOGIN_NEW_LOCATION,
            emitter: $options['emitter'] ?? self::DEFAULT_EMITTER,
            userId: $userId,
            details: $city !== null ? ['country' => $country, 'city' => $city] : ['country' => $country],
        ));

        if ($options['notify'] ?? true) {
            $this->_send($user, $country, $city, $options);
        }

        return true;
    }

    /**
     * Returns whether a resolved location is one the user had never signed in
     * from before.
     *
     * A user's first-ever sign-in is never new — there is no baseline to compare
     * against, and alerting someone about the only place they have ever used is
     * noise. No country (no geo database, or an IP that could not be placed) is
     * never new either, so an install without location awareness never flags
     * anything. Otherwise a location is new when no prior row for the user shares
     * this exact country and city.
     *
     * @param int $userId the user signing in
     * @param string|null $country the resolved ISO country, or null
     * @param string|null $city the resolved city, or null
     * @param Query<int, array<string, mixed>>|null $history a query over the consumer's own login history,
     * which must expose `userId`, `country`, and `city` columns; null reads the
     * shared `authkit_locations` history
     * @return bool
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    public function isNew(int $userId, ?string $country, ?string $city, ?Query $history = null): bool
    {
        if ($country === null) {
            return false;
        }

        $history ??= (new Query())->from(Table::LOCATIONS);

        $hadPrior = (clone $history)
            ->andWhere(['userId' => $userId])
            ->exists();

        if (!$hadPrior) {
            return false;
        }

        $seenThisLocation = (clone $history)
            ->andWhere(['userId' => $userId, 'country' => $country, 'city' => $city])
            ->exists();

        return !$seenThisLocation;
    }

    /**
     * Remembers that a user has been seen at a coarse location, creating the
     * shared history row the first time and touching it on every later sign-in
     * from the same place.
     *
     * Called from [[Sessions::record()]], so the shared history covers every
     * channel a member can sign in through — password, magic link, one-time
     * code, passkey — not just the ones one plugin happens to own.
     *
     * A null country is not a location and is ignored. The write is best-effort:
     * a failure here must never disturb a login already completed.
     *
     * @param int $userId the user who signed in
     * @param string|null $country the resolved ISO country, or null
     * @param string|null $city the resolved city, or null
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    public function seen(int $userId, ?string $country, ?string $city): void
    {
        if ($country === null) {
            return;
        }

        try {
            $record = $this->_record($userId, $country, $city) ?? $this->_newRecord($userId, $country, $city);
            $record->save(false);
        } catch (Throwable $e) {
            Craft::warning("Could not record the sign-in location for user {$userId}: {$e->getMessage()}", __METHOD__);
        }
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns whether a location was already alerted about inside the dedupe
     * window.
     *
     * @param LocationRecord $record the shared location row
     * @return bool
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    private function _alertedRecently(LocationRecord $record): bool
    {
        if ($record->dateAlerted === null) {
            return false;
        }

        // The column holds a naive UTC string while the process timezone is the
        // system timezone, so the zone must be named at parse time.
        $alertedAt = Carbon::createFromFormat('Y-m-d H:i:s', $record->dateAlerted, 'UTC');

        return $alertedAt !== false && $alertedAt->diffInSeconds(Carbon::now(), true) < $this->alertWindow;
    }

    /**
     * Claims the right to alert about a location, returning the stamped record,
     * or null when another consumer already claimed it inside [[$alertWindow]]
     * (or the write failed).
     *
     * @param int $userId the user the location belongs to
     * @param string $country the resolved ISO country
     * @param string|null $city the resolved city, or null
     * @return LocationRecord|null
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    private function _claim(int $userId, string $country, ?string $city): ?LocationRecord
    {
        try {
            $record = $this->_record($userId, $country, $city) ?? $this->_newRecord($userId, $country, $city);

            if ($this->_alertedRecently($record)) {
                return null;
            }

            $record->dateAlerted = Db::prepareDateForDb(Carbon::now());
            $record->save(false);

            return $record;
        } catch (Throwable $e) {
            Craft::warning("Could not claim the new-location alert for user {$userId}: {$e->getMessage()}", __METHOD__);

            return null;
        }
    }

    /**
     * Returns an unsaved history row for a user and place.
     *
     * @param int $userId the user the location belongs to
     * @param string $country the resolved ISO country
     * @param string|null $city the resolved city, or null
     * @return LocationRecord
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    private function _newRecord(int $userId, string $country, ?string $city): LocationRecord
    {
        $record = new LocationRecord();
        $record->userId = $userId;
        $record->country = $country;
        $record->city = $city;

        return $record;
    }

    /**
     * Returns the stored history row for a user and place, or null when the
     * user has never been seen there.
     *
     * @param int $userId the user the location belongs to
     * @param string $country the resolved ISO country
     * @param string|null $city the resolved city, or null
     * @return LocationRecord|null
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    private function _record(int $userId, string $country, ?string $city): ?LocationRecord
    {
        /** @var LocationRecord|null $record */
        $record = LocationRecord::findOne(['userId' => $userId, 'country' => $country, 'city' => $city]);

        return $record;
    }

    /**
     * Emails a member that their account was signed in to from a new location.
     *
     * Best-effort and self-contained: a missing address or a delivery failure is
     * logged and swallowed so it can never disturb the login it reports on. The
     * message body and subject are editable through Craft's system messages.
     *
     * @param User $user the member to alert
     * @param string $country the resolved ISO country
     * @param string|null $city the resolved city, or null
     * @param array{messageKey?: string, sessionsUrl?: string} $options per-call options
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    private function _send(User $user, string $country, ?string $city, array $options): void
    {
        if ($user->email === null || $user->email === '') {
            return;
        }

        $location = $city !== null ? "$city, $country" : $country;

        try {
            Craft::$app->getMailer()
                ->composeFromKey($options['messageKey'] ?? self::MESSAGE_KEY_NEW_LOCATION, [
                    'user' => $user,
                    'city' => (string)$city,
                    'country' => $country,
                    'location' => $location,
                    'sessionsUrl' => $options['sessionsUrl'] ?? UrlHelper::siteUrl(),
                ])
                ->setTo($user)
                ->send();
        } catch (Throwable $e) {
            Craft::error("Could not send the new-location alert for user {$user->id}: {$e->getMessage()}", __METHOD__);
        }
    }
}
