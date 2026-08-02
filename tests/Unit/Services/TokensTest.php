<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * SLOW-MODE test matrix for the tokens service. Passwordless tokens are a
 * security boundary (CLAUDE.md): the failure paths are tested first and
 * exhaustively — expired, already-consumed, tampered/unknown token,
 * single-use, ineligible users — alongside the issue-side enumeration
 * behaviour, the OTP attempt/supersede semantics, and the happy-path round
 * trip for both token types.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craft\elements\User;
use craft\helpers\Db;
use craft\helpers\StringHelper;
use craftpulse\authkit\events\TokenEvent;
use craftpulse\authkit\models\Token;
use craftpulse\authkit\records\Token as TokenRecord;
use craftpulse\authkit\services\Tokens;
use craftpulse\authkit\tests\Support\CollectingMailer;
use craftpulse\authkit\tests\Support\CountingSecurity;
use yii\base\Event;

function tokens(?CollectingMailer $mailer = null): Tokens
{
    return new Tokens(['mailer' => $mailer ?? new CollectingMailer()]);
}

function tokenUser(string $status = User::STATUS_ACTIVE): User
{
    $unique = str_replace('-', '', StringHelper::UUID());
    $user = new User();
    $user->username = "tk-{$unique}@authkit-test.example";
    $user->email = "tk-{$unique}@authkit-test.example";

    if (!Craft::$app->getElements()->saveElement($user)) {
        throw new RuntimeException('Could not save token test user.');
    }

    Craft::$app->getUsers()->activateUser($user);

    if ($status === User::STATUS_SUSPENDED) {
        Craft::$app->getUsers()->suspendUser($user);
    }

    return Craft::$app->getUsers()->getUserById((int)$user->id);
}

/**
 * Computes the stored hash for a raw token, mirroring the service's scheme:
 * an OTP digest is scoped to its user's UID (the code pool is tiny and
 * deterministic), a magic-link secret is hashed bare.
 */
function storedHash(int $userId, string $rawToken, string $type = Token::TYPE_MAGIC_LINK): string
{
    if ($type !== Token::TYPE_OTP) {
        return hash('sha256', $rawToken);
    }

    $user = Craft::$app->getUsers()->getUserById($userId);

    return hash('sha256', $user->uid . ':' . $rawToken);
}

/**
 * Inserts a token row directly, so consume()'s failure paths can be exercised
 * without round-tripping through issue().
 */
function insertToken(
    int $userId,
    string $rawToken,
    string $type = Token::TYPE_MAGIC_LINK,
    string $expiryModifier = '+15 minutes',
    bool $consumed = false,
    ?int $maxAttempts = null,
    int $attempts = 0,
): void {
    $record = new TokenRecord();
    $record->userId = $userId;
    $record->type = $type;
    $record->tokenHash = storedHash($userId, $rawToken, $type);
    $record->expiryDate = Db::prepareDateForDb((new DateTime())->modify($expiryModifier));
    $record->dateConsumed = $consumed ? Db::prepareDateForDb(new DateTime()) : null;
    $record->attempts = $attempts;
    $record->maxAttempts = $maxAttempts;
    $record->save(false);
}

afterEach(function() {
    foreach (User::find()->email('*@authkit-test.example')->status(null)->all() as $user) {
        Craft::$app->getElements()->deleteElement($user, true);
    }
});

// Magic link — issue
// =========================================================================

it('issues a usable, hashed, single-use magic link and emails it to an active user', function() {
    $user = tokenUser();
    $mailer = new CollectingMailer();

    $issued = tokens($mailer)->issueMagicLink($user->email);

    expect($issued)->toBeTrue()
        ->and($mailer->sent)->toHaveCount(1)
        ->and($mailer->lastRecipients())->toContain($user->email);

    $link = $mailer->lastLink();
    expect($link)->toBeString();

    parse_str((string)parse_url($link, PHP_URL_QUERY), $query);
    $rawToken = $query[Tokens::TOKEN_PARAM] ?? null;
    expect($rawToken)->toBeString();

    $record = TokenRecord::findOne(['tokenHash' => hash('sha256', $rawToken)]);
    expect($record)->not->toBeNull()
        ->and($record->userId)->toBe((int)$user->id)
        ->and($record->type)->toBe(Token::TYPE_MAGIC_LINK)
        ->and($record->dateConsumed)->toBeNull();

    // The raw token must never be what is stored.
    expect(TokenRecord::findOne(['tokenHash' => $rawToken]))->toBeNull();
});

it('carries a returnUrl through to the link and payload', function() {
    $user = tokenUser();
    $mailer = new CollectingMailer();

    tokens($mailer)->issueMagicLink($user->email, '/dashboard');

    parse_str((string)parse_url($mailer->lastLink(), PHP_URL_QUERY), $query);
    expect($query['returnUrl'] ?? null)->toBe('/dashboard');

    $record = TokenRecord::findOne(['tokenHash' => hash('sha256', $query[Tokens::TOKEN_PARAM])]);
    $model = Token::fromRecord($record);
    expect($model->payload)->toBe(['returnUrl' => '/dashboard']);
});

it('never uses Craft\'s reserved token param in the magic-link URL', function() {
    // Craft's web application intercepts any request whose `tokenParam`
    // (default `token`) query param is present and responds 400 when it is
    // not a Craft routed token — a magic link named that way can never reach
    // the consuming controller. Found live in the Warden phase-2 E2E drive.
    $user = tokenUser();
    $mailer = new CollectingMailer();

    tokens($mailer)->issueMagicLink($user->email);

    parse_str((string)parse_url($mailer->lastLink(), PHP_URL_QUERY), $query);
    $craftTokenParam = Craft::$app->getConfig()->getGeneral()->tokenParam;

    expect($query)->toHaveKey(Tokens::TOKEN_PARAM)
        ->and(Tokens::TOKEN_PARAM)->not->toBe($craftTokenParam)
        ->and($query)->not->toHaveKey($craftTokenParam);
});

it('does not issue or email a magic link for an unknown address, without throwing', function() {
    $mailer = new CollectingMailer();

    // Delta-based: the playground DB may hold real token rows outside the
    // suite's control, so assert nothing NEW was stored.
    $before = (int)TokenRecord::find()->count();

    $issued = tokens($mailer)->issueMagicLink('nobody-' . StringHelper::UUID() . '@authkit-test.example');

    expect($issued)->toBeFalse()
        ->and($mailer->sent)->toHaveCount(0)
        ->and((int)TokenRecord::find()->count())->toBe($before);
});

it('fails closed and issues no magic link for a suspended user', function() {
    $user = tokenUser(User::STATUS_SUSPENDED);
    $mailer = new CollectingMailer();

    $issued = tokens($mailer)->issueMagicLink($user->email);

    expect($issued)->toBeFalse()
        ->and($mailer->sent)->toHaveCount(0)
        ->and((int)TokenRecord::find()->where(['userId' => $user->id])->count())->toBe(0);
});

it('throttles repeated issues to the same address within the window', function() {
    $user = tokenUser();
    $service = tokens();
    $service->perEmailLimit = 2;

    expect($service->issueMagicLink($user->email))->toBeTrue()
        ->and($service->issueMagicLink($user->email))->toBeTrue()
        ->and($service->issueMagicLink($user->email))->toBeFalse();
});

// Magic link — consume round trip + single use
// =========================================================================

it('consumes a freshly issued magic link exactly once', function() {
    $user = tokenUser();
    $mailer = new CollectingMailer();
    $service = tokens($mailer);

    $service->issueMagicLink($user->email);
    parse_str((string)parse_url($mailer->lastLink(), PHP_URL_QUERY), $query);
    $rawToken = $query[Tokens::TOKEN_PARAM];

    $first = $service->consumeMagicLink($rawToken);
    expect($first)->toBeInstanceOf(User::class)
        ->and($first->id)->toBe($user->id);

    // Single-use: the second attempt with the same token is refused.
    expect($service->consumeMagicLink($rawToken))->toBeNull();
});

// Magic link — consume failure matrix
// =========================================================================

it('refuses an expired magic link', function() {
    $user = tokenUser();
    insertToken((int)$user->id, 'raw-expired-token', expiryModifier: '-1 second');

    expect(tokens()->consumeMagicLink('raw-expired-token'))->toBeNull();
});

it('refuses an already-consumed magic link', function() {
    $user = tokenUser();
    insertToken((int)$user->id, 'raw-consumed-token', consumed: true);

    expect(tokens()->consumeMagicLink('raw-consumed-token'))->toBeNull();
});

it('refuses an unknown or tampered magic link', function() {
    $user = tokenUser();
    insertToken((int)$user->id, 'the-real-token');

    expect(tokens()->consumeMagicLink('a-different-token'))->toBeNull();
});

it('refuses a valid magic link whose user is now suspended', function() {
    $user = tokenUser();
    insertToken((int)$user->id, 'raw-suspended-token');
    Craft::$app->getUsers()->suspendUser($user);

    expect(tokens()->consumeMagicLink('raw-suspended-token'))->toBeNull();
});

it('refuses a valid magic link whose user is now locked, burning the token', function() {
    // getStatus() folds a lock into "active", so a locked account would slip
    // past the active-status check — the explicit lock check keeps a stale token
    // from logging in behind a lockout. The burn still happens (mirror of the
    // suspended path), so the token cannot be replayed once the lock lifts.
    $user = tokenUser();
    insertToken((int)$user->id, 'raw-locked-token');

    Craft::$app->getDb()->createCommand()
        ->update('{{%users}}', ['locked' => true, 'lockoutDate' => Db::prepareDateForDb(new DateTime())], ['id' => $user->id])
        ->execute();

    expect(tokens()->consumeMagicLink('raw-locked-token'))->toBeNull();

    $record = TokenRecord::findOne(['tokenHash' => hash('sha256', 'raw-locked-token')]);
    expect($record->dateConsumed)->not->toBeNull();
});

it('lets a before-consume handler cancel the login without burning the token', function() {
    $user = tokenUser();
    insertToken((int)$user->id, 'raw-cancel-token');

    $handler = function(TokenEvent $event): void {
        $event->isValid = false;
    };
    Event::on(Tokens::class, Tokens::EVENT_BEFORE_CONSUME_TOKEN, $handler);

    try {
        expect(tokens()->consumeMagicLink('raw-cancel-token'))->toBeNull();

        $record = TokenRecord::findOne(['tokenHash' => hash('sha256', 'raw-cancel-token')]);
        expect($record->dateConsumed)->toBeNull();
    } finally {
        Event::off(Tokens::class, Tokens::EVENT_BEFORE_CONSUME_TOKEN, $handler);
    }
});

// OTP — issue
// =========================================================================

it('issues a numeric OTP code with an attempt cap and emails it', function() {
    $user = tokenUser();
    $mailer = new CollectingMailer();

    $issued = tokens($mailer)->issueOtp($user->email);

    expect($issued)->toBeTrue()
        ->and($mailer->sent)->toHaveCount(1)
        ->and($mailer->lastRecipients())->toContain($user->email);

    $code = $mailer->lastCode();
    expect($code)->toBeString()
        ->and($code)->toMatch('/^\d{6}$/');

    $record = TokenRecord::findOne(['tokenHash' => storedHash((int)$user->id, $code, Token::TYPE_OTP), 'type' => Token::TYPE_OTP]);
    expect($record)->not->toBeNull()
        ->and((int)$record->maxAttempts)->toBe(5)
        ->and($record->dateConsumed)->toBeNull();

    // The bare (unscoped) code hash must never be what is stored — it would
    // collide across users on the unique tokenHash index.
    expect(TokenRecord::findOne(['tokenHash' => hash('sha256', $code), 'type' => Token::TYPE_OTP]))->toBeNull();
});

it('issues the same OTP code to two users without colliding, and each consumes only their own', function() {
    // The stored hash is scoped per user: with a bare sha256 of the 6-digit
    // code, the second insert here would violate the unique tokenHash index
    // and 500 the issue endpoint.
    $alice = tokenUser();
    $bob = tokenUser();

    insertToken((int)$alice->id, '123456', type: Token::TYPE_OTP, maxAttempts: 5);
    insertToken((int)$bob->id, '123456', type: Token::TYPE_OTP, maxAttempts: 5);

    $aliceHash = TokenRecord::findOne(['userId' => $alice->id, 'type' => Token::TYPE_OTP])->tokenHash;
    $bobHash = TokenRecord::findOne(['userId' => $bob->id, 'type' => Token::TYPE_OTP])->tokenHash;
    expect($aliceHash)->not->toBe($bobHash);

    $service = tokens();

    // Each user consumes their own code; one burn does not touch the other.
    $first = $service->consumeOtp($alice->email, '123456');
    expect($first)->toBeInstanceOf(User::class)
        ->and($first->id)->toBe($alice->id);

    $second = $service->consumeOtp($bob->email, '123456');
    expect($second)->toBeInstanceOf(User::class)
        ->and($second->id)->toBe($bob->id);
});

it('does not issue an OTP for an unknown address', function() {
    $mailer = new CollectingMailer();

    $issued = tokens($mailer)->issueOtp('nobody-' . StringHelper::UUID() . '@authkit-test.example');

    expect($issued)->toBeFalse()
        ->and($mailer->sent)->toHaveCount(0);
});

it('supersedes a prior unconsumed OTP when a new one is issued', function() {
    $user = tokenUser();
    $mailer = new CollectingMailer();
    $service = tokens($mailer);

    $service->issueOtp($user->email);
    $firstCode = $mailer->lastCode();

    $service->issueOtp($user->email);
    $secondCode = $mailer->lastCode();

    // The old code can no longer log in; only the newest is live.
    expect($service->consumeOtp($user->email, $firstCode))->toBeNull()
        ->and($service->consumeOtp($user->email, $secondCode))->toBeInstanceOf(User::class);
});

// OTP — consume round trip + single use
// =========================================================================

it('consumes a correct OTP code once within the cap', function() {
    $user = tokenUser();
    $mailer = new CollectingMailer();
    $service = tokens($mailer);

    $service->issueOtp($user->email);
    $code = $mailer->lastCode();

    $first = $service->consumeOtp($user->email, $code);
    expect($first)->toBeInstanceOf(User::class)
        ->and($first->id)->toBe($user->id);

    // Single-use: the same code cannot be replayed.
    expect($service->consumeOtp($user->email, $code))->toBeNull();
});

// OTP — attempt cap
// =========================================================================

it('increments attempts on a wrong OTP code', function() {
    $user = tokenUser();
    insertToken((int)$user->id, '123456', type: Token::TYPE_OTP, maxAttempts: 5);

    expect(tokens()->consumeOtp($user->email, '999999'))->toBeNull();

    $record = TokenRecord::findOne(['userId' => $user->id, 'type' => Token::TYPE_OTP]);
    expect((int)$record->attempts)->toBe(1)
        ->and($record->dateConsumed)->toBeNull();
});

it('burns the OTP and fails closed once maxAttempts is exceeded', function() {
    $user = tokenUser();
    insertToken((int)$user->id, '123456', type: Token::TYPE_OTP, maxAttempts: 3);
    $service = tokens();

    // Three wrong guesses exhaust the budget and burn the code.
    $service->consumeOtp($user->email, '000000');
    $service->consumeOtp($user->email, '000001');
    $service->consumeOtp($user->email, '000002');

    $record = TokenRecord::findOne(['userId' => $user->id, 'type' => Token::TYPE_OTP]);
    expect((int)$record->attempts)->toBe(3)
        ->and($record->dateConsumed)->not->toBeNull();

    // Even the correct code now fails closed — the token is burned.
    expect($service->consumeOtp($user->email, '123456'))->toBeNull();
});

it('refuses an OTP for an unknown address', function() {
    expect(tokens()->consumeOtp('nobody-' . StringHelper::UUID() . '@authkit-test.example', '123456'))->toBeNull();
});

it('refuses an expired OTP code', function() {
    $user = tokenUser();
    insertToken((int)$user->id, '123456', type: Token::TYPE_OTP, expiryModifier: '-1 second', maxAttempts: 5);

    expect(tokens()->consumeOtp($user->email, '123456'))->toBeNull();
});

// Enumeration timing
// =========================================================================

/**
 * Swaps in a security spy, runs the callback, restores the real component,
 * and returns how many fixed-cost bcrypt verifications the callback made.
 */
function countEqualizerCalls(callable $callback): int
{
    $spy = new CountingSecurity();
    Craft::$app->set('security', $spy);

    try {
        $callback();
    } finally {
        Craft::$app->set('security', ['class' => craft\services\Security::class]);
    }

    return $spy->validatePasswordCalls;
}

it('equalizes timing when consuming an OTP whose record is expired or burned', function() {
    // A fast return on the "record exists but is stale" branch would let an
    // attacker distinguish an account with OTP history (fast) from an unknown
    // address (slow bcrypt equalizer) — an account-existence oracle. Every
    // failure branch of consumeOtp must perform exactly one verification.
    $expiredUser = tokenUser();
    insertToken((int)$expiredUser->id, '123456', type: Token::TYPE_OTP, expiryModifier: '-1 second', maxAttempts: 5);

    $burnedUser = tokenUser();
    insertToken((int)$burnedUser->id, '654321', type: Token::TYPE_OTP, consumed: true, maxAttempts: 5);

    $service = tokens();

    expect(countEqualizerCalls(fn() => $service->consumeOtp($expiredUser->email, '123456')))->toBe(1)
        ->and(countEqualizerCalls(fn() => $service->consumeOtp($burnedUser->email, '654321')))->toBe(1);
});

it('equalizes timing when a wrong OTP code is submitted against a live token', function() {
    // The wrong-code branch's failed-attempt bookkeeping is two indexed
    // single-row UPDATEs (single-digit ms). Without the equalizer it returns
    // fast while the unknown-address path pays a ~100ms+ bcrypt — a working
    // account-existence oracle. This branch too must perform exactly one
    // verification.
    $user = tokenUser();
    insertToken((int)$user->id, '123456', type: Token::TYPE_OTP, maxAttempts: 5);

    $service = tokens();

    expect(countEqualizerCalls(fn() => $service->consumeOtp($user->email, '999999')))->toBe(1);
});

it('equalizes timing across the unknown-address and no-token OTP consume paths', function() {
    $noTokenUser = tokenUser();
    $service = tokens();

    expect(countEqualizerCalls(fn() => $service->consumeOtp('nobody-' . StringHelper::UUID() . '@authkit-test.example', '123456')))->toBe(1)
        ->and(countEqualizerCalls(fn() => $service->consumeOtp($noTokenUser->email, '123456')))->toBe(1);
});

it('equalizes timing when issuing to an unknown or suspended address', function() {
    $suspended = tokenUser(User::STATUS_SUSPENDED);
    $service = tokens();

    expect(countEqualizerCalls(fn() => $service->issueMagicLink('nobody-' . StringHelper::UUID() . '@authkit-test.example')))->toBe(1)
        ->and(countEqualizerCalls(fn() => $service->issueMagicLink($suspended->email)))->toBe(1)
        ->and(countEqualizerCalls(fn() => $service->issueOtp('nobody-' . StringHelper::UUID() . '@authkit-test.example')))->toBe(1);
});

it('spends real bcrypt cost on the unknown-address path, not a no-op', function() {
    // The equalizer must stay a genuine fixed-cost verification: DUMMY_HASH is
    // cost-13 bcrypt, which cannot complete in under ~30ms on any hardware
    // this runs on. Guards against the equalizer being refactored into
    // something instant, which would silently reopen the timing oracle.
    $service = tokens();

    $start = hrtime(true);
    $service->issueMagicLink('nobody-' . StringHelper::UUID() . '@authkit-test.example');
    $elapsedMs = (hrtime(true) - $start) / 1_000_000;

    expect($elapsedMs)->toBeGreaterThan(30.0);
});

// Maintenance
// =========================================================================

it('purges expired tokens and leaves usable ones', function() {
    $user = tokenUser();
    insertToken((int)$user->id, 'raw-stale', expiryModifier: '-1 hour');
    insertToken((int)$user->id, 'raw-fresh', expiryModifier: '+1 hour');

    $deleted = tokens()->purgeExpiredTokens();

    expect($deleted)->toBeGreaterThanOrEqual(1)
        ->and(TokenRecord::findOne(['tokenHash' => hash('sha256', 'raw-fresh')]))->not->toBeNull()
        ->and(TokenRecord::findOne(['tokenHash' => hash('sha256', 'raw-stale')]))->toBeNull();
});

it('prunes expired tokens when Craft garbage collection runs', function() {
    $user = tokenUser();
    insertToken((int)$user->id, 'gc-stale', expiryModifier: '-1 hour');
    insertToken((int)$user->id, 'gc-fresh', expiryModifier: '+1 hour');

    // The plugin wires purgeExpiredTokens() onto Gc::EVENT_RUN; a forced GC
    // pass must fire it and clear the stale row while sparing the usable one.
    Craft::$app->getGc()->run(true);

    expect(TokenRecord::findOne(['tokenHash' => hash('sha256', 'gc-stale')]))->toBeNull()
        ->and(TokenRecord::findOne(['tokenHash' => hash('sha256', 'gc-fresh')]))->not->toBeNull();
});
