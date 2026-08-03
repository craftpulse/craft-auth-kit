<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Test matrix for the email-bound guest OTP (1.6.0). A guest code proves
 * control of an ARBITRARY mailbox — member or external, no user required — and
 * never logs anyone in or mints a session. The suite mirrors the user-bound
 * OTP matrix: issue/consume happy path, the attempt cap, per-email supersede,
 * single-use, expiry, origin isolation, GC, the enumeration-safe timing
 * profile, and the no-user (external email) round trip the whole primitive
 * exists for.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craft\helpers\Db;
use craft\helpers\StringHelper;
use craftpulse\authkit\models\Token;
use craftpulse\authkit\records\Token as TokenRecord;
use craftpulse\authkit\services\Tokens;
use craftpulse\authkit\tests\Support\CollectingMailer;
use craftpulse\authkit\tests\Support\CountingSecurity;

/**
 * Local helpers — deliberately self-contained so this file never depends on
 * another test file having been loaded first.
 */
function guestTokens(?CollectingMailer $mailer = null): Tokens
{
    return new Tokens(['mailer' => $mailer ?? new CollectingMailer()]);
}

/**
 * A fresh external email that maps to no Craft user.
 */
function guestEmail(): string
{
    return 'guest-' . str_replace('-', '', StringHelper::UUID()) . '@external.example';
}

/**
 * The subject the service keys a guest OTP by — the sha256 of the lowercased
 * email.
 */
function guestSubject(string $email): string
{
    return hash('sha256', strtolower(trim($email)));
}

/**
 * Inserts a guest OTP row directly, so consume()'s failure paths can be
 * exercised without round-tripping through issue().
 */
function insertGuestToken(
    string $email,
    string $code,
    string $origin = 'warrant',
    string $expiryModifier = '+15 minutes',
    bool $consumed = false,
    ?int $maxAttempts = 5,
    int $attempts = 0,
): void {
    $record = new TokenRecord();
    $record->userId = null;
    $record->type = Token::TYPE_GUEST_OTP;
    $record->origin = $origin;
    $record->subject = guestSubject($email);
    $record->tokenHash = hash('sha256', strtolower(trim($email)) . ':' . $code);
    $record->expiryDate = Db::prepareDateForDb((new DateTime())->modify($expiryModifier));
    $record->dateConsumed = $consumed ? Db::prepareDateForDb(new DateTime()) : null;
    $record->attempts = $attempts;
    $record->maxAttempts = $maxAttempts;
    $record->save(false);
}

/**
 * Swaps in a security spy, runs the callback, restores the real component, and
 * returns how many fixed-cost bcrypt verifications the callback made.
 */
function countGuestEqualizerCalls(callable $callback): int
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

// Guest OTP — issue
// =========================================================================

it('issues a numeric guest OTP for an external non-user email and emails it', function() {
    $email = guestEmail();
    $mailer = new CollectingMailer();

    // No user exists for this address — that is the whole point.
    expect(Craft::$app->getUsers()->getUserByUsernameOrEmail($email))->toBeNull();

    guestTokens($mailer)->issueGuestOtp($email, 'warrant');

    expect($mailer->sent)->toHaveCount(1)
        ->and($mailer->lastRecipients())->toContain($email);

    $code = $mailer->lastCode();
    expect($code)->toBeString()
        ->and($code)->toMatch('/^\d{6}$/');

    $record = TokenRecord::findOne([
        'type' => Token::TYPE_GUEST_OTP,
        'subject' => guestSubject($email),
    ]);
    expect($record)->not->toBeNull()
        ->and($record->userId)->toBeNull()
        ->and((int)$record->maxAttempts)->toBe(5)
        ->and($record->dateConsumed)->toBeNull();
});

it('stores no raw email, only a hashed subject and an email-scoped code hash', function() {
    $email = guestEmail();
    $mailer = new CollectingMailer();

    guestTokens($mailer)->issueGuestOtp($email, 'warrant');
    $code = (string)$mailer->lastCode();

    $record = TokenRecord::findOne(['type' => Token::TYPE_GUEST_OTP, 'subject' => guestSubject($email)]);

    // The subject is a digest, not the address; the payload holds nothing.
    expect($record->subject)->not->toBe($email)
        ->and($record->subject)->toBe(guestSubject($email))
        ->and($record->payload)->toBeNull();

    // The bare (unscoped) code hash must never be what is stored — it would
    // collide across mailboxes on the unique tokenHash index.
    expect(TokenRecord::findOne(['tokenHash' => hash('sha256', $code), 'type' => Token::TYPE_GUEST_OTP]))->toBeNull();
    expect($record->tokenHash)->toBe(hash('sha256', strtolower($email) . ':' . $code));
});

it('issues the same guest code to two mailboxes without colliding, each consumes only its own', function() {
    // The stored hash is scoped per email: with a bare sha256 of the 6-digit
    // code, the second insert here would violate the unique tokenHash index.
    $alice = guestEmail();
    $bob = guestEmail();

    insertGuestToken($alice, '123456');
    insertGuestToken($bob, '123456');

    $aliceHash = TokenRecord::findOne(['subject' => guestSubject($alice), 'type' => Token::TYPE_GUEST_OTP])->tokenHash;
    $bobHash = TokenRecord::findOne(['subject' => guestSubject($bob), 'type' => Token::TYPE_GUEST_OTP])->tokenHash;
    expect($aliceHash)->not->toBe($bobHash);

    $service = guestTokens();

    expect($service->consumeGuestOtp($alice, '123456', 'warrant'))->toBeTrue()
        ->and($service->consumeGuestOtp($bob, '123456', 'warrant'))->toBeTrue();
});

it('supersedes a prior unconsumed guest OTP when a new one is issued', function() {
    $email = guestEmail();
    $mailer = new CollectingMailer();
    $service = guestTokens($mailer);

    $service->issueGuestOtp($email, 'warrant');
    $firstCode = (string)$mailer->lastCode();

    $service->issueGuestOtp($email, 'warrant');
    $secondCode = (string)$mailer->lastCode();

    // The old code is dead; only the newest verifies.
    expect($service->consumeGuestOtp($email, $firstCode, 'warrant'))->toBeFalse()
        ->and($service->consumeGuestOtp($email, $secondCode, 'warrant'))->toBeTrue();
});

it('throttles repeated guest issues to the same email within the window', function() {
    $email = guestEmail();
    $service = guestTokens();
    $service->perEmailLimit = 2;

    $service->issueGuestOtp($email, 'warrant');
    $service->issueGuestOtp($email, 'warrant');
    $service->issueGuestOtp($email, 'warrant');

    // Only two rows were ever written; the third issue was dropped by the throttle.
    expect((int)TokenRecord::find()->where(['subject' => guestSubject($email), 'type' => Token::TYPE_GUEST_OTP])->count())->toBe(2);
});

it('drops a malformed guest email silently without issuing or throwing', function() {
    $mailer = new CollectingMailer();
    $before = (int)TokenRecord::find()->count();

    guestTokens($mailer)->issueGuestOtp('not-an-email', 'warrant');

    expect($mailer->sent)->toHaveCount(0)
        ->and((int)TokenRecord::find()->count())->toBe($before);
});

it('rejects a malformed origin on guest issue', function() {
    guestTokens()->issueGuestOtp(guestEmail(), str_repeat('x', 33));
})->throws(InvalidArgumentException::class);

// Guest OTP — consume round trip + single use
// =========================================================================

it('consumes a freshly issued external guest OTP end to end, exactly once', function() {
    $email = guestEmail();
    $mailer = new CollectingMailer();
    $service = guestTokens($mailer);

    $service->issueGuestOtp($email, 'warrant');
    $code = (string)$mailer->lastCode();

    expect($service->consumeGuestOtp($email, $code, 'warrant'))->toBeTrue();

    // Single-use: the same code cannot be replayed.
    expect($service->consumeGuestOtp($email, $code, 'warrant'))->toBeFalse();
});

// Guest OTP — attempt cap
// =========================================================================

it('increments attempts on a wrong guest code', function() {
    $email = guestEmail();
    insertGuestToken($email, '123456', maxAttempts: 5);

    expect(guestTokens()->consumeGuestOtp($email, '999999', 'warrant'))->toBeFalse();

    $record = TokenRecord::findOne(['subject' => guestSubject($email), 'type' => Token::TYPE_GUEST_OTP]);
    expect((int)$record->attempts)->toBe(1)
        ->and($record->dateConsumed)->toBeNull();
});

it('burns the guest OTP and fails closed once maxAttempts is exceeded', function() {
    $email = guestEmail();
    insertGuestToken($email, '123456', maxAttempts: 3);
    $service = guestTokens();

    $service->consumeGuestOtp($email, '000000', 'warrant');
    $service->consumeGuestOtp($email, '000001', 'warrant');
    $service->consumeGuestOtp($email, '000002', 'warrant');

    $record = TokenRecord::findOne(['subject' => guestSubject($email), 'type' => Token::TYPE_GUEST_OTP]);
    expect((int)$record->attempts)->toBe(3)
        ->and($record->dateConsumed)->not->toBeNull();

    // Even the correct code now fails closed — the code is burned.
    expect($service->consumeGuestOtp($email, '123456', 'warrant'))->toBeFalse();
});

// Guest OTP — consume failure matrix
// =========================================================================

it('refuses a guest code for an email that was never issued one', function() {
    expect(guestTokens()->consumeGuestOtp(guestEmail(), '123456', 'warrant'))->toBeFalse();
});

it('refuses an expired guest OTP code', function() {
    $email = guestEmail();
    insertGuestToken($email, '123456', expiryModifier: '-1 second');

    expect(guestTokens()->consumeGuestOtp($email, '123456', 'warrant'))->toBeFalse();
});

it('refuses an already-consumed guest OTP code', function() {
    $email = guestEmail();
    insertGuestToken($email, '123456', consumed: true);

    expect(guestTokens()->consumeGuestOtp($email, '123456', 'warrant'))->toBeFalse();
});

// Guest OTP — origin isolation
// =========================================================================

it('refuses a guest code at another origin and leaves it unburned for its own', function() {
    $email = guestEmail();
    insertGuestToken($email, '123456', origin: 'warrant');
    $service = guestTokens();

    // Presented at the wrong consumer's endpoint: refused AND left unburned.
    expect($service->consumeGuestOtp($email, '123456', 'other'))->toBeFalse();

    $record = TokenRecord::findOne(['subject' => guestSubject($email), 'type' => Token::TYPE_GUEST_OTP]);
    expect($record->dateConsumed)->toBeNull();

    // Its rightful origin still verifies it.
    expect($service->consumeGuestOtp($email, '123456', 'warrant'))->toBeTrue();
});

it('does not let per-origin guest codes supersede each other', function() {
    $email = guestEmail();
    $service = guestTokens(new CollectingMailer());

    // Two live codes for the same email under different origins.
    insertGuestToken($email, '111111', origin: 'warrant');
    insertGuestToken($email, '222222', origin: 'other');

    // Each origin only ever sees and burns its own code.
    expect($service->consumeGuestOtp($email, '111111', 'warrant'))->toBeTrue()
        ->and($service->consumeGuestOtp($email, '222222', 'other'))->toBeTrue();
});

// Guest OTP — enumeration timing
// =========================================================================

it('equalizes timing across every guest consume failure branch', function() {
    // A guest OTP has no account to enumerate, but the failure branches must
    // still be uniform: an attacker probing for "does a live code exist for
    // this mailbox" must not distinguish the branches by timing. Every failure
    // performs exactly one fixed-cost verification.
    $noToken = guestEmail();

    $wrongCode = guestEmail();
    insertGuestToken($wrongCode, '123456', maxAttempts: 5);

    $stale = guestEmail();
    insertGuestToken($stale, '654321', expiryModifier: '-1 second');

    $service = guestTokens();

    expect(countGuestEqualizerCalls(fn() => $service->consumeGuestOtp($noToken, '123456', 'warrant')))->toBe(1)
        ->and(countGuestEqualizerCalls(fn() => $service->consumeGuestOtp($wrongCode, '999999', 'warrant')))->toBe(1)
        ->and(countGuestEqualizerCalls(fn() => $service->consumeGuestOtp($stale, '654321', 'warrant')))->toBe(1);
});

// Guest OTP — maintenance / GC
// =========================================================================

it('purges expired guest tokens and leaves usable ones', function() {
    $stale = guestEmail();
    $fresh = guestEmail();
    insertGuestToken($stale, '123456', expiryModifier: '-1 hour');
    insertGuestToken($fresh, '654321', expiryModifier: '+1 hour');

    guestTokens()->purgeExpiredTokens();

    expect(TokenRecord::findOne(['subject' => guestSubject($stale), 'type' => Token::TYPE_GUEST_OTP]))->toBeNull()
        ->and(TokenRecord::findOne(['subject' => guestSubject($fresh), 'type' => Token::TYPE_GUEST_OTP]))->not->toBeNull();
});

it('prunes expired guest tokens when Craft garbage collection runs', function() {
    $stale = guestEmail();
    $fresh = guestEmail();
    insertGuestToken($stale, '123456', expiryModifier: '-1 hour');
    insertGuestToken($fresh, '654321', expiryModifier: '+1 hour');

    Craft::$app->getGc()->run(true);

    expect(TokenRecord::findOne(['subject' => guestSubject($stale), 'type' => Token::TYPE_GUEST_OTP]))->toBeNull()
        ->and(TokenRecord::findOne(['subject' => guestSubject($fresh), 'type' => Token::TYPE_GUEST_OTP]))->not->toBeNull();
});
