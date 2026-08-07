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
use craft\db\Table as CraftTable;
use craft\elements\User;
use craft\helpers\Db;
use craft\web\Request as WebRequest;
use craftpulse\authkit\audit\AuthEvent;
use craftpulse\authkit\AuthKit;
use craftpulse\authkit\db\Table;
use craftpulse\authkit\helpers\Device;
use craftpulse\authkit\helpers\Ip;
use craftpulse\authkit\models\SessionInfo;
use craftpulse\authkit\records\Session as SessionRecord;
use Throwable;
use yii\base\Component;

/**
 * Sessions owns the shared device registry behind every session-management
 * screen on the install. Core's `{{%sessions}}` table stores only a token and
 * its timestamps — no device information — so the registry keeps a parallel row
 * pinning the sha256 hash of each Craft auth-session token to the device that
 * produced it. The two are joined at read time by re-hashing each live core
 * token.
 *
 * One registry, however many consumers. [[record()]] is idempotent on the token
 * hash, so Warden and Warp can both wire it to `EVENT_AFTER_LOGIN` and a login
 * still produces exactly one row, one device card, and (through
 * [[Locations]]) one new-location alert. Capture is deliberately not wired
 * here: a consumer owns when it captures and what its privacy settings say
 * about the stored address, and Auth Kit ships no behavior nobody asked for.
 * Orphan pruning, which belongs to whoever owns the table, is wired by Auth Kit
 * itself.
 *
 * Deleting a `{{%sessions}}` row is the authoritative server-side kill: Craft
 * validates its session token against that table on every authenticated request,
 * so a browser whose row is gone is a guest on its next request. The registry
 * stores only the hash, so revocation re-derives the match by hashing the user's
 * live tokens — a registry leak yields no usable token.
 *
 * Ownership is always scoped in the query, never trusted from a posted uid: a
 * user can only ever reach their own rows. Recording is best-effort — a
 * bookkeeping failure must never block a login already completed.
 *
 * An instance is available via `AuthKit::$plugin->getSessions()`.
 *
 * @author CraftPulse
 * @since 1.10.0
 */
class Sessions extends Component
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
     * @var int The maximum stored length of a captured user-agent string.
     *
     * @since 1.10.0
     */
    private const USER_AGENT_MAX_LENGTH = 255;

    // Public Methods
    // =========================================================================

    /**
     * Returns a user's active sessions as [[SessionInfo]] models, the current
     * session first and the rest by most recently seen.
     *
     * The list is core's `{{%sessions}}` rows for the user, each joined to its
     * registry row (when one exists) for the device label and IP. A core session
     * with no registry row — one created before the registry existed, or by a
     * path no consumer captures — still appears, labelled "Unknown device" with a
     * null uid, so nothing is hidden from the person managing their account.
     *
     * @param User $user the user whose sessions to list
     * @return array<int, SessionInfo> the user's active sessions
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    public function getSessionsForUser(User $user): array
    {
        $userId = (int)$user->id;
        $currentHash = $this->_currentTokenHash();

        $coreRows = (new Query())
            ->select(['token', 'dateUpdated'])
            ->from(CraftTable::SESSIONS)
            ->where(['userId' => $userId])
            ->all();

        /** @var array<string, array<string, mixed>> $registry */
        $registry = (new Query())
            ->select(['uid', 'tokenHash', 'userAgent', 'ip', 'city', 'isNewLocation'])
            ->from(Table::SESSIONS)
            ->where(['userId' => $userId])
            ->indexBy('tokenHash')
            ->all();

        $sessions = array_map(
            fn(array $row): SessionInfo => $this->_toSessionInfo($row, $registry, $currentHash),
            $coreRows,
        );

        usort($sessions, static function(SessionInfo $a, SessionInfo $b): int {
            if ($a->isCurrent !== $b->isCurrent) {
                return $a->isCurrent ? -1 : 1;
            }

            return ($b->lastSeen?->getTimestamp() ?? 0) <=> ($a->lastSeen?->getTimestamp() ?? 0);
        });

        return $sessions;
    }

    /**
     * Prunes orphaned registry rows — rows whose core `{{%sessions}}` row no
     * longer exists.
     *
     * Wired to `craft\services\Gc::EVENT_RUN`, so it rides Craft's own garbage
     * collection: core purges stale `{{%sessions}}` rows first, then this clears
     * the registry rows left pointing at nothing. The match cannot be expressed
     * in SQL (core stores the raw token, the registry the hash), so live tokens
     * are hashed into a set and non-matching registry rows are dropped —
     * acceptable for a background pass over a small registry.
     *
     * Guarded on the table existing, because this is the one path Auth Kit runs
     * on its own initiative. A module has no schema version for Craft to watch,
     * so its tables arrive only when a consumer's migration brings them up —
     * and an install carrying this release of Auth Kit alongside a consumer that
     * has not yet adopted it has the code without the table. Garbage collection
     * must not start throwing on that install.
     *
     * @return int the number of registry rows deleted
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    public function pruneOrphans(): int
    {
        if (!Craft::$app->getDb()->tableExists(Table::SESSIONS)) {
            return 0;
        }

        $liveHashes = [];

        foreach ((new Query())->select(['token'])->from(CraftTable::SESSIONS)->column() as $token) {
            $liveHashes[hash('sha256', (string)$token)] = true;
        }

        $deleted = 0;

        $rows = (new Query())
            ->select(['id', 'tokenHash'])
            ->from(Table::SESSIONS)
            ->all();

        foreach ($rows as $row) {
            if (!isset($liveHashes[$row['tokenHash']])) {
                $deleted += Db::delete(Table::SESSIONS, ['id' => $row['id']]);
            }
        }

        return $deleted;
    }

    /**
     * Forgets the registry row for a Craft session token — called on logout,
     * where core deletes its own `{{%sessions}}` row and the registry row would
     * otherwise be left orphaned until garbage collection.
     *
     * @param string $token Craft's auth-session token
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    public function pruneToken(string $token): void
    {
        Db::delete(Table::SESSIONS, ['tokenHash' => hash('sha256', $token)]);
    }

    /**
     * Records the current request's session against the device that made it —
     * the sha256 hash of Craft's freshly issued auth-session token, plus a
     * truncated user-agent and IP for display — and remembers the coarse
     * location it came from in the shared history.
     *
     * The row also records whether that location was one the user had never been
     * seen at, so every consumer badges and filters on one stored answer rather
     * than each recomputing its own. The order the two location steps run in is
     * load-bearing: [[Locations::isNew()]] is asked first, and only then does
     * [[Locations::seen()]] file the place into the history. Reversed, the place
     * is already in the history by the time the question is asked and the answer
     * is always false.
     *
     * Call it from `WebUser::EVENT_AFTER_LOGIN`, by which point core has already
     * generated the token and inserted the `{{%sessions}}` row. Best-effort and
     * null-guarded: no token (a console or session-less context) or an already
     * recorded hash is a silent no-op, and a failed registry read or write is
     * logged and swallowed so it never blocks a login.
     *
     * @param array{anonymizeIp?: bool} $options per-call options: `anonymizeIp`
     * whether the stored address is coarsened before it is written, which
     * defaults to true. The geo lookup always runs on the full address first, so
     * the resolved location is the same either way.
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    public function record(array $options = []): void
    {
        $userSession = $this->_userSession();
        $token = $userSession->getToken();

        if ($token === null) {
            return;
        }

        $user = $userSession->getIdentity();

        if (!$user instanceof User) {
            return;
        }

        $tokenHash = hash('sha256', $token);
        $request = Craft::$app->getRequest();
        $userAgent = null;
        $ip = null;

        if ($request instanceof WebRequest) {
            $userAgent = $request->getUserAgent();
            $ip = $request->getUserIP();
        }

        // Bookkeeping must never block a login already completed, so the registry
        // read and write are wrapped: any failure is logged and swallowed.
        try {
            if (SessionRecord::find()->where(['tokenHash' => $tokenHash])->exists()) {
                return;
            }

            $module = AuthKit::getInstance();
            $location = $module->getGeo()->lookup($ip);
            $locations = $module->getLocations();

            // ORDER IS LOAD-BEARING. The question "has this account ever been
            // seen here?" can only be asked of a history this place is not in
            // yet, so isNew() must run before seen() files it. Swap the two and
            // the answer is always false, silently and forever.
            $isNewLocation = $locations->isNew((int)$user->id, $location['country'], $location['city']);

            $record = new SessionRecord();
            $record->userId = (int)$user->id;
            $record->tokenHash = $tokenHash;
            $record->userAgent = $userAgent !== null ? mb_substr($userAgent, 0, self::USER_AGENT_MAX_LENGTH) : null;
            // The geo lookup above ran on the full address; only the stored
            // copy is coarsened when anonymization is enabled.
            $record->ip = ($options['anonymizeIp'] ?? true) ? Ip::anonymize($ip) : $ip;
            $record->city = $location['city'];
            $record->country = $location['country'];
            $record->isNewLocation = $isNewLocation;
            $record->save(false);

            // The registry is the one capture every login channel passes
            // through, so it is where the shared location history is fed from.
            // Alerting is not done here: a consumer owns whether its members get
            // told, and Locations::alert() keeps two consumers to one email.
            $locations->seen((int)$user->id, $location['country'], $location['city']);
        } catch (Throwable $e) {
            Craft::warning("Could not record the session for user {$user->id}: {$e->getMessage()}", __METHOD__);
        }
    }

    /**
     * Revokes one of a user's sessions by its registry uid.
     *
     * Ownership is scoped in the lookup — the row must match both the uid and the
     * user — so a posted uid alone can never reach another user's session. When
     * it matches, the core `{{%sessions}}` row is deleted via its stored hash
     * (the authoritative kill) and the registry row with it. A uid that resolves
     * to no owned row is a no-op returning false.
     *
     * @param User $user the user revoking a session
     * @param string $uid the registry uid of the session to revoke
     * @param array{emitter?: string} $options per-call options: `emitter` the
     * consumer's handle, recorded against the audit fact
     * @return bool whether a session was revoked
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    public function revoke(User $user, string $uid, array $options = []): bool
    {
        $userId = (int)$user->id;

        $row = (new Query())
            ->select(['id', 'tokenHash'])
            ->from(Table::SESSIONS)
            ->where(['uid' => $uid, 'userId' => $userId])
            ->one();

        if ($row === null) {
            return false;
        }

        $this->_deleteCraftSession($userId, (string)$row['tokenHash']);
        Db::delete(Table::SESSIONS, ['id' => $row['id']]);
        $this->_recordRevocation($userId, 'single', $options);

        return true;
    }

    /**
     * Revokes every session a user holds except the one making the current
     * request — the "sign out everywhere else" action.
     *
     * Walks the user's core `{{%sessions}}` rows, skips the current token, and
     * deletes each other row (the authoritative kill) along with its registry
     * row. Rows with no registry entry are still revoked — the delete keys on the
     * core row, so an unknown device is signed out too.
     *
     * @param User $user the user signing out their other sessions
     * @param array{emitter?: string} $options per-call options: `emitter` the
     * consumer's handle, recorded against the audit fact
     * @return int the number of sessions revoked
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    public function revokeOthers(User $user, array $options = []): int
    {
        $userId = (int)$user->id;
        $currentHash = $this->_currentTokenHash();

        $coreRows = (new Query())
            ->select(['id', 'token'])
            ->from(CraftTable::SESSIONS)
            ->where(['userId' => $userId])
            ->all();

        $revoked = 0;

        foreach ($coreRows as $row) {
            $hash = hash('sha256', (string)$row['token']);

            if ($currentHash !== null && hash_equals($currentHash, $hash)) {
                continue;
            }

            Db::delete(CraftTable::SESSIONS, ['id' => $row['id']]);
            Db::delete(Table::SESSIONS, ['userId' => $userId, 'tokenHash' => $hash]);
            $revoked++;
        }

        // Only a genuine revocation is an audit fact — "sign out everywhere else"
        // that found nothing to sign out (only the current session) records
        // nothing.
        if ($revoked > 0) {
            $this->_recordRevocation($userId, 'others', $options);
        }

        return $revoked;
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the sha256 hash of the current request's session token, or null
     * when there is no session token (a guest or session-less context).
     *
     * @return string|null
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    private function _currentTokenHash(): ?string
    {
        $token = $this->_userSession()->getToken();

        return $token !== null ? hash('sha256', $token) : null;
    }

    /**
     * Deletes the core `{{%sessions}}` row matching a stored token hash.
     *
     * The registry stores only hashes, so the match is re-derived by hashing the
     * user's live core tokens — a user rarely holds more than a handful.
     * Comparison is constant-time as basic hygiene, though the hashes compared
     * here are not secret-bearing.
     *
     * @param int $userId the user the session belongs to
     * @param string $tokenHash the sha256 hash of the session token to kill
     * @return int the number of core session rows deleted (0 or 1)
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    private function _deleteCraftSession(int $userId, string $tokenHash): int
    {
        $candidates = (new Query())
            ->select(['id', 'token'])
            ->from(CraftTable::SESSIONS)
            ->where(['userId' => $userId])
            ->all();

        foreach ($candidates as $candidate) {
            if (hash_equals($tokenHash, hash('sha256', (string)$candidate['token']))) {
                return Db::delete(CraftTable::SESSIONS, ['id' => $candidate['id']]);
            }
        }

        return 0;
    }

    /**
     * Records a session revocation as an audit fact through Auth Kit's neutral
     * contract — a no-op with no sinks registered. Only genuine revocations
     * reach here (the callers gate on a real kill), never a no-op.
     *
     * @param int $userId the user whose session was revoked
     * @param string $scope the revocation scope — `single` or `others`
     * @param array{emitter?: string} $options the caller's per-call options
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    private function _recordRevocation(int $userId, string $scope, array $options): void
    {
        AuthKit::getInstance()->getAudit()->record(new AuthEvent(
            name: AuthEvent::SESSION_REVOKED,
            emitter: $options['emitter'] ?? self::DEFAULT_EMITTER,
            userId: $userId,
            details: ['scope' => $scope],
        ));
    }

    /**
     * Maps one core `{{%sessions}}` row to a [[SessionInfo]], joining its
     * registry entry for device metadata and flagging the current session.
     *
     * @param array<string, mixed> $row the core session row, with `token` and `dateUpdated`
     * @param array<string, array<string, mixed>> $registry the user's registry rows, keyed by token hash
     * @param string|null $currentHash the hash of the current request's token, or null
     * @return SessionInfo
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    private function _toSessionInfo(array $row, array $registry, ?string $currentHash): SessionInfo
    {
        $hash = hash('sha256', (string)$row['token']);
        $match = $registry[$hash] ?? null;
        $lastSeen = $row['dateUpdated'] ?? null;

        $userAgent = $match !== null && $match['userAgent'] !== null ? (string)$match['userAgent'] : null;

        $info = new SessionInfo();
        $info->uid = $match !== null ? (string)$match['uid'] : null;
        $info->ip = $match !== null && $match['ip'] !== null ? (string)$match['ip'] : null;
        $info->city = $match !== null && $match['city'] !== null ? (string)$match['city'] : null;
        // Null stays null: "never assessed" is not "was not new".
        $info->isNewLocation = $match !== null && $match['isNewLocation'] !== null ? (bool)$match['isNewLocation'] : null;
        $info->deviceLabel = $match !== null
            ? Device::label($userAgent)
            : Craft::t('auth-kit', 'Unknown device');
        $info->deviceType = Device::type($userAgent);
        // The column holds a naive UTC string while the process timezone is
        // the system timezone, so the zone must be named at parse time.
        $info->lastSeen = is_string($lastSeen) ? Carbon::parse($lastSeen, 'UTC') : null;
        $info->isCurrent = $currentHash !== null && hash_equals($currentHash, $hash);

        return $info;
    }

    /**
     * Returns the web user session component, narrowed for static analysis —
     * this service only ever runs on web requests.
     *
     * @return \craft\web\User
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    private function _userSession(): \craft\web\User
    {
        $userSession = Craft::$app->getUser();
        assert($userSession instanceof \craft\web\User);

        return $userSession;
    }
}
