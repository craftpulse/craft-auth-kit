<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
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
    $record->tokenHash = hash('sha256', $rawToken);
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
    $rawToken = $query['token'] ?? null;
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

    $record = TokenRecord::findOne(['tokenHash' => hash('sha256', $query['token'])]);
    $model = Token::fromRecord($record);
    expect($model->payload)->toBe(['returnUrl' => '/dashboard']);
});

it('does not issue or email a magic link for an unknown address, without throwing', function() {
    $mailer = new CollectingMailer();

    $issued = tokens($mailer)->issueMagicLink('nobody-' . StringHelper::UUID() . '@authkit-test.example');

    expect($issued)->toBeFalse()
        ->and($mailer->sent)->toHaveCount(0)
        ->and((int)TokenRecord::find()->count())->toBe(0);
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
    $rawToken = $query['token'];

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

    $record = TokenRecord::findOne(['tokenHash' => hash('sha256', $code), 'type' => Token::TYPE_OTP]);
    expect($record)->not->toBeNull()
        ->and((int)$record->maxAttempts)->toBe(5)
        ->and($record->dateConsumed)->toBeNull();
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
