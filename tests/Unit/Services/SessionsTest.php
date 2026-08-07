<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Service tests for the shared device registry. The matrix pins the
 * security-load-bearing behaviour: capture hashes the live token and is
 * idempotent (so two consumers wiring it produce one row), the stored address is
 * anonymized unless the caller opts out, revocation is ownership-scoped in the
 * query (a user can never reach another's session), revoking deletes the
 * authoritative core row, "everywhere else" spares the current session, listing
 * flags the current one and falls back for unknown devices, and garbage
 * collection clears orphaned registry rows.
 *
 * Core sessions are inserted directly — the same shape
 * `craft\web\User::generateToken()` writes on login — so the service can be
 * exercised without a full browser session, and the current request's token is
 * simulated on the session component the service reads through.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craft\db\Query;
use craft\db\Table as CraftTable;
use craft\elements\User;
use craft\helpers\Db;
use craft\helpers\StringHelper;
use craftpulse\authkit\audit\AuthEvent;
use craftpulse\authkit\AuthKit;
use craftpulse\authkit\db\Table;
use craftpulse\authkit\models\SessionInfo;
use craftpulse\authkit\records\Session as SessionRecord;
use craftpulse\authkit\services\Geo;
use craftpulse\authkit\services\Locations;
use craftpulse\authkit\services\Sessions;
use craftpulse\authkit\tests\Support\CollectingAuditSink;

function registryUser(): User
{
    $unique = str_replace('-', '', StringHelper::UUID());
    $user = new User();
    $user->username = "sess-{$unique}@authkit-test.example";
    $user->email = "sess-{$unique}@authkit-test.example";

    if (!Craft::$app->getElements()->saveElement($user)) {
        throw new RuntimeException('Could not save registry test user.');
    }

    Craft::$app->getUsers()->activateUser($user);

    return Craft::$app->getUsers()->getUserById((int)$user->id);
}

function insertCoreSession(int $userId): string
{
    $token = 'tok-' . bin2hex(random_bytes(32));
    Db::insert(CraftTable::SESSIONS, ['userId' => $userId, 'token' => $token]);

    return $token;
}

function insertRegistryRow(int $userId, string $token, ?string $userAgent = null, ?string $ip = null): string
{
    $record = new SessionRecord();
    $record->userId = $userId;
    $record->tokenHash = hash('sha256', $token);
    $record->userAgent = $userAgent;
    $record->ip = $ip;
    $record->save(false);

    return $record->uid;
}

function setCurrentToken(string $token): void
{
    Craft::$app->getSession()->set(Craft::$app->getUser()->tokenParam, $token);
}

function coreSessionExists(string $token): bool
{
    return (new Query())->from(CraftTable::SESSIONS)->where(['token' => $token])->exists();
}

function registryExistsForToken(string $token): bool
{
    return (new Query())->from(Table::SESSIONS)->where(['tokenHash' => hash('sha256', $token)])->exists();
}

/**
 * Returns the stored new-location flag for a token's registry row. MySQL hands
 * a `tinyint(1)` back as an int, so the two answers are normalized to booleans
 * — but null is passed through untouched, because "never assessed" is the one
 * value this column must never collapse into "not new".
 */
function storedNewLocationFlag(string $token): ?bool
{
    $value = SessionRecord::findOne(['tokenHash' => hash('sha256', $token)])?->isNewLocation;

    return $value === null ? null : (bool)$value;
}

/**
 * Plants a known client address on the request and resets getUserIP()'s memo on
 * both sides, then restores everything.
 */
function withClientIp(string $ip, callable $body): void
{
    $request = Craft::$app->getRequest();
    $memo = new ReflectionProperty(craft\web\Request::class, '_ipAddress');
    $memo->setValue($request, null);
    $original = $request->getHeaders()->get('X-Forwarded-For');
    $request->getHeaders()->set('X-Forwarded-For', $ip);

    try {
        $body();
    } finally {
        $request->getHeaders()->set('X-Forwarded-For', $original);
        $memo->setValue($request, null);
    }
}

/**
 * Swaps a geo service that resolves every address to one fixed place onto the
 * module, then restores the real one. No MMDB ships with the suite, so this is
 * the only way to exercise the location-bearing half of a capture.
 */
function withResolvedLocation(string $country, ?string $city, callable $body): void
{
    $module = AuthKit::getInstance();
    $original = $module->getGeo();

    $stub = new class() extends Geo {
        public ?string $stubCity = null;
        public string $stubCountry = '';

        public function lookup(?string $ip): array
        {
            return ['city' => $this->stubCity, 'country' => $this->stubCountry];
        }
    };

    $stub->stubCountry = $country;
    $stub->stubCity = $city;
    $module->set('geo', $stub);

    try {
        $body();
    } finally {
        $module->set('geo', $original);
    }
}

beforeEach(function() {
    Craft::$app->getUser()->setIdentity(null);
    Craft::$app->getSession()->remove(Craft::$app->getUser()->tokenParam);
});

afterEach(function() {
    Craft::$app->getUser()->setIdentity(null);
    Craft::$app->getSession()->remove(Craft::$app->getUser()->tokenParam);

    foreach (User::find()->email('*@authkit-test.example')->status(null)->all() as $user) {
        Craft::$app->getElements()->deleteElement($user, true);
    }

    AuthKit::$plugin->getAudit()->setSinks([]);
});

// =============================================================================
// capture
// =============================================================================

it('records the current session against its device on login', function() {
    $user = registryUser();
    $token = insertCoreSession((int)$user->id);
    Craft::$app->getUser()->setIdentity($user);
    setCurrentToken($token);
    Craft::$app->getRequest()->getHeaders()->set('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36');

    try {
        (new Sessions())->record();
    } finally {
        Craft::$app->getRequest()->getHeaders()->remove('User-Agent');
    }

    $record = SessionRecord::findOne(['tokenHash' => hash('sha256', $token)]);

    expect($record)->not->toBeNull()
        ->and((int)$record->userId)->toBe((int)$user->id)
        ->and($record->userAgent)->toContain('Chrome');
});

it('anonymizes the stored IP by default', function() {
    $user = registryUser();
    $token = insertCoreSession((int)$user->id);
    Craft::$app->getUser()->setIdentity($user);
    setCurrentToken($token);

    withClientIp('203.0.113.45', function() {
        (new Sessions())->record();
    });

    expect(SessionRecord::findOne(['tokenHash' => hash('sha256', $token)])->ip)->toBe('203.0.113.0');
});

it('keeps the full address when the caller opts out', function() {
    $user = registryUser();
    $token = insertCoreSession((int)$user->id);
    Craft::$app->getUser()->setIdentity($user);
    setCurrentToken($token);

    withClientIp('203.0.113.45', function() {
        (new Sessions())->record(['anonymizeIp' => false]);
    });

    expect(SessionRecord::findOne(['tokenHash' => hash('sha256', $token)])->ip)->toBe('203.0.113.45');
});

it('records one row however many consumers capture the same login', function() {
    $user = registryUser();
    $token = insertCoreSession((int)$user->id);
    Craft::$app->getUser()->setIdentity($user);
    setCurrentToken($token);

    // Two consumers, each wiring the capture to EVENT_AFTER_LOGIN.
    (new Sessions())->record();
    (new Sessions())->record();

    $count = (new Query())->from(Table::SESSIONS)->where(['tokenHash' => hash('sha256', $token)])->count();

    expect((int)$count)->toBe(1);
});

it('records nothing with no session token', function() {
    $user = registryUser();
    Craft::$app->getUser()->setIdentity($user);

    (new Sessions())->record();

    expect((new Query())->from(Table::SESSIONS)->where(['userId' => (int)$user->id])->exists())->toBeFalse();
});

// =============================================================================
// new-location flag — asked BEFORE the place is filed into the history
// =============================================================================

it('flags a session recorded from a place the user has never been', function() {
    $user = registryUser();
    $token = insertCoreSession((int)$user->id);
    Craft::$app->getUser()->setIdentity($user);
    setCurrentToken($token);

    // A baseline, so the rule has something to compare against — a first-ever
    // sign-in is never new.
    (new Locations())->seen((int)$user->id, 'BE', 'Brussels');

    withResolvedLocation('JP', 'Tokyo', function() {
        (new Sessions())->record();
    });

    // This is the ordering guard. record() asks Locations::isNew() and only
    // then calls Locations::seen(). Swap those two lines in the service and
    // Tokyo is already in the history by the time the question is asked, the
    // answer comes back false, and this expectation fails.
    expect(storedNewLocationFlag($token))->toBe(true);
});

it('still files the place into the shared history after asking', function() {
    $user = registryUser();
    $token = insertCoreSession((int)$user->id);
    Craft::$app->getUser()->setIdentity($user);
    setCurrentToken($token);

    (new Locations())->seen((int)$user->id, 'BE', 'Brussels');

    withResolvedLocation('JP', 'Tokyo', function() {
        (new Sessions())->record();
    });

    // Asking first must not cost the history the row: the next sign-in from
    // Tokyo has to read as familiar.
    expect((new Locations())->isNew((int)$user->id, 'JP', 'Tokyo'))->toBeFalse();
});

it('does not flag a session recorded from a place already in the history', function() {
    $user = registryUser();
    $token = insertCoreSession((int)$user->id);
    Craft::$app->getUser()->setIdentity($user);
    setCurrentToken($token);

    (new Locations())->seen((int)$user->id, 'BE', 'Brussels');
    (new Locations())->seen((int)$user->id, 'JP', 'Tokyo');

    withResolvedLocation('JP', 'Tokyo', function() {
        (new Sessions())->record();
    });

    expect(storedNewLocationFlag($token))->toBe(false);
});

it('does not flag a first-ever sign-in, which has no baseline to be new against', function() {
    $user = registryUser();
    $token = insertCoreSession((int)$user->id);
    Craft::$app->getUser()->setIdentity($user);
    setCurrentToken($token);

    withResolvedLocation('JP', 'Tokyo', function() {
        (new Sessions())->record();
    });

    expect(storedNewLocationFlag($token))->toBe(false);
});

it('records a resolved-nothing capture as not new, reserving null for rows that predate the column', function() {
    $user = registryUser();
    $token = insertCoreSession((int)$user->id);
    Craft::$app->getUser()->setIdentity($user);
    setCurrentToken($token);

    // No geo database: the real service resolves nothing.
    (new Sessions())->record();

    expect(storedNewLocationFlag($token))->toBe(false);
});

it('surfaces the flag on the session list, keeping an unassessed row null', function() {
    $user = registryUser();
    $flagged = insertCoreSession((int)$user->id);
    $legacy = insertCoreSession((int)$user->id);
    Craft::$app->getUser()->setIdentity($user);
    setCurrentToken($flagged);

    // A row from before the column existed: captured, never assessed.
    insertRegistryRow((int)$user->id, $legacy);

    (new Locations())->seen((int)$user->id, 'BE', 'Brussels');

    withResolvedLocation('JP', 'Tokyo', function() {
        (new Sessions())->record();
    });

    $list = (new Sessions())->getSessionsForUser($user);
    $flaggedInfo = array_values(array_filter($list, static fn(SessionInfo $info): bool => $info->isCurrent))[0];
    $legacyInfo = array_values(array_filter($list, static fn(SessionInfo $info): bool => !$info->isCurrent))[0];

    expect($flaggedInfo->isNewLocation)->toBe(true)
        ->and($legacyInfo->isNewLocation)->toBeNull();
});

// =============================================================================
// revoke — ownership scoped
// =============================================================================

it('refuses to revoke a session that belongs to another user', function() {
    $alice = registryUser();
    $bob = registryUser();
    $bobToken = insertCoreSession((int)$bob->id);
    $bobUid = insertRegistryRow((int)$bob->id, $bobToken);

    $revoked = (new Sessions())->revoke($alice, $bobUid);

    expect($revoked)->toBeFalse()
        ->and(coreSessionExists($bobToken))->toBeTrue()
        ->and(registryExistsForToken($bobToken))->toBeTrue();
});

it('revokes an owned session, deleting the core row so the browser is a guest next request', function() {
    $user = registryUser();
    $token = insertCoreSession((int)$user->id);
    $uid = insertRegistryRow((int)$user->id, $token);

    $revoked = (new Sessions())->revoke($user, $uid);

    // The core {{%sessions}} row gone is the authoritative kill: Craft validates
    // the token against that table on every request, so the browser is a guest.
    expect($revoked)->toBeTrue()
        ->and(coreSessionExists($token))->toBeFalse()
        ->and(registryExistsForToken($token))->toBeFalse();
});

it('returns false revoking an unknown uid', function() {
    expect((new Sessions())->revoke(registryUser(), StringHelper::UUID()))->toBeFalse();
});

// =============================================================================
// revoke others — spares current
// =============================================================================

it('signs out every session except the current one', function() {
    $user = registryUser();
    $current = insertCoreSession((int)$user->id);
    $other1 = insertCoreSession((int)$user->id);
    $other2 = insertCoreSession((int)$user->id);
    insertRegistryRow((int)$user->id, $current);
    insertRegistryRow((int)$user->id, $other1);
    insertRegistryRow((int)$user->id, $other2);
    Craft::$app->getUser()->setIdentity($user);
    setCurrentToken($current);

    $count = (new Sessions())->revokeOthers($user);

    expect($count)->toBe(2)
        ->and(coreSessionExists($current))->toBeTrue()
        ->and(coreSessionExists($other1))->toBeFalse()
        ->and(coreSessionExists($other2))->toBeFalse()
        ->and(registryExistsForToken($current))->toBeTrue()
        ->and(registryExistsForToken($other1))->toBeFalse();
});

it('signs out an unknown device with no registry row through revoke others', function() {
    $user = registryUser();
    $current = insertCoreSession((int)$user->id);
    $unknown = insertCoreSession((int)$user->id);
    insertRegistryRow((int)$user->id, $current);
    Craft::$app->getUser()->setIdentity($user);
    setCurrentToken($current);

    $count = (new Sessions())->revokeOthers($user);

    expect($count)->toBe(1)
        ->and(coreSessionExists($unknown))->toBeFalse();
});

// =============================================================================
// audit emission — a genuine revocation records session.revoked
// =============================================================================

it('records a session.revoked audit event under the calling consumer handle', function() {
    $sink = new CollectingAuditSink();
    AuthKit::$plugin->getAudit()->setSinks([$sink]);

    $user = registryUser();
    $token = insertCoreSession((int)$user->id);
    $uid = insertRegistryRow((int)$user->id, $token);

    (new Sessions())->revoke($user, $uid, ['emitter' => 'warden']);

    $event = $sink->firstOfName(AuthEvent::SESSION_REVOKED);

    expect($event)->not->toBeNull()
        ->and($event->emitter)->toBe('warden')
        ->and($event->outcome)->toBe(AuthEvent::OUTCOME_SUCCESS)
        ->and($event->userId)->toBe((int)$user->id)
        ->and($event->details)->toBe(['scope' => 'single']);
});

it('falls back to the module handle when no consumer names itself', function() {
    $sink = new CollectingAuditSink();
    AuthKit::$plugin->getAudit()->setSinks([$sink]);

    $user = registryUser();
    $token = insertCoreSession((int)$user->id);
    $uid = insertRegistryRow((int)$user->id, $token);

    (new Sessions())->revoke($user, $uid);

    expect($sink->firstOfName(AuthEvent::SESSION_REVOKED)->emitter)->toBe(Sessions::DEFAULT_EMITTER);
});

it('records no audit event revoking an unknown uid', function() {
    $sink = new CollectingAuditSink();
    AuthKit::$plugin->getAudit()->setSinks([$sink]);

    (new Sessions())->revoke(registryUser(), StringHelper::UUID());

    expect($sink->events)->toBe([]);
});

it('records a session.revoked audit event with scope others when it signs out others', function() {
    $sink = new CollectingAuditSink();
    AuthKit::$plugin->getAudit()->setSinks([$sink]);

    $user = registryUser();
    $current = insertCoreSession((int)$user->id);
    $other = insertCoreSession((int)$user->id);
    insertRegistryRow((int)$user->id, $current);
    insertRegistryRow((int)$user->id, $other);
    Craft::$app->getUser()->setIdentity($user);
    setCurrentToken($current);

    (new Sessions())->revokeOthers($user);

    $event = $sink->firstOfName(AuthEvent::SESSION_REVOKED);

    expect($event)->not->toBeNull()
        ->and($event->userId)->toBe((int)$user->id)
        ->and($event->details)->toBe(['scope' => 'others']);
});

it('records no audit event when revoke others finds only the current session', function() {
    $sink = new CollectingAuditSink();
    AuthKit::$plugin->getAudit()->setSinks([$sink]);

    $user = registryUser();
    $current = insertCoreSession((int)$user->id);
    insertRegistryRow((int)$user->id, $current);
    Craft::$app->getUser()->setIdentity($user);
    setCurrentToken($current);

    expect((new Sessions())->revokeOthers($user))->toBe(0)
        ->and($sink->events)->toBe([]);
});

// =============================================================================
// listing
// =============================================================================

it('lists sessions, flagging the current one and labelling unknown devices', function() {
    $user = registryUser();
    $current = insertCoreSession((int)$user->id);
    $known = insertCoreSession((int)$user->id);
    insertCoreSession((int)$user->id); // no registry row -> unknown device
    $currentUid = insertRegistryRow((int)$user->id, $current, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36', '203.0.113.4');
    insertRegistryRow((int)$user->id, $known, 'Mozilla/5.0 (Windows NT 10.0; rv:121.0) Gecko/20100101 Firefox/121.0');
    Craft::$app->getUser()->setIdentity($user);
    setCurrentToken($current);

    $sessions = (new Sessions())->getSessionsForUser($user);

    expect($sessions)->toHaveCount(3)
        ->and($sessions[0]->isCurrent)->toBeTrue()
        ->and($sessions[0]->uid)->toBe($currentUid)
        ->and($sessions[0]->deviceLabel)->toBe('Chrome on macOS')
        ->and($sessions[0]->ip)->toBe('203.0.113.4');

    $unknown = array_values(array_filter($sessions, static fn($info): bool => $info->uid === null));

    expect($unknown)->toHaveCount(1)
        ->and($unknown[0]->deviceLabel)->toBe('Unknown device');
});

// =============================================================================
// pruning
// =============================================================================

it('forgets a registry row for a token on logout', function() {
    $user = registryUser();
    $token = insertCoreSession((int)$user->id);
    insertRegistryRow((int)$user->id, $token);

    (new Sessions())->pruneToken($token);

    expect(registryExistsForToken($token))->toBeFalse();
});

it('prunes registry rows whose core session no longer exists on garbage collection', function() {
    $user = registryUser();
    $live = insertCoreSession((int)$user->id);
    insertRegistryRow((int)$user->id, $live);

    // An orphan: a registry row pointing at a core session that never existed.
    $orphanToken = 'tok-' . bin2hex(random_bytes(32));
    insertRegistryRow((int)$user->id, $orphanToken);

    // Auth Kit owns the table, so it owns the sweep — a forced GC pass must
    // clear the orphan without any consumer wiring one of its own.
    Craft::$app->getGc()->run(true);

    expect(registryExistsForToken($live))->toBeTrue()
        ->and(registryExistsForToken($orphanToken))->toBeFalse();
});
