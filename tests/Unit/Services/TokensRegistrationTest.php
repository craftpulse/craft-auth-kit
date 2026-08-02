<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * SLOW-MODE test matrix for the registration token type. Registration is a
 * security boundary (CLAUDE.md): the failure paths are tested first and
 * exhaustively — an address that already has an account (of any status),
 * expired / already-consumed / unknown tokens, single-use, and a canceled
 * before-consume — alongside the issue-side enumeration timing parity and the
 * happy-path round trip.
 *
 * The `tokens()`, `tokenUser()`, and `countEqualizerCalls()` helpers are shared
 * with TokensTest.php (both files load for the whole suite); only the
 * registration-specific fixtures are defined here.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craft\elements\User;
use craft\helpers\Db;
use craft\helpers\Json;
use craft\helpers\StringHelper;
use craftpulse\authkit\events\TokenEvent;
use craftpulse\authkit\models\Token;
use craftpulse\authkit\records\Token as TokenRecord;
use craftpulse\authkit\services\Tokens;
use craftpulse\authkit\tests\Support\CollectingMailer;
use yii\base\Event;

/**
 * Returns a fresh, never-activated (pending) user, so the "address already has
 * an account of any status" refusal can be exercised for a pending row too.
 */
function pendingTokenUser(): User
{
    $unique = str_replace('-', '', StringHelper::UUID());
    $user = new User();
    $user->username = "tk-{$unique}@authkit-test.example";
    $user->email = "tk-{$unique}@authkit-test.example";
    $user->pending = true;

    if (!Craft::$app->getElements()->saveElement($user)) {
        throw new RuntimeException('Could not save pending token test user.');
    }

    return Craft::$app->getUsers()->getUserById((int)$user->id);
}

/**
 * Returns an email address with no account behind it.
 */
function unknownEmail(): string
{
    return 'nobody-' . StringHelper::UUID() . '@authkit-test.example';
}

/**
 * Inserts a registration token row directly (null userId, bare sha256 hash,
 * email in the payload), so consumeRegistration()'s failure paths can be
 * exercised without round-tripping through issue().
 */
function insertRegistrationToken(
    string $rawToken,
    string $expiryModifier = '+15 minutes',
    bool $consumed = false,
    string $email = 'newcomer@authkit-test.example',
): void {
    $record = new TokenRecord();
    $record->userId = null;
    $record->type = Token::TYPE_REGISTER;
    $record->tokenHash = hash('sha256', $rawToken);
    $record->expiryDate = Db::prepareDateForDb((new DateTime())->modify($expiryModifier));
    $record->dateConsumed = $consumed ? Db::prepareDateForDb(new DateTime()) : null;
    $record->attempts = 0;
    $record->maxAttempts = null;
    $record->payload = Json::encode(['email' => $email]);
    $record->save(false);
}

/**
 * Extracts the raw token from a registration link's query string.
 */
function rawTokenFromLink(?string $link): ?string
{
    parse_str((string)parse_url((string)$link, PHP_URL_QUERY), $query);

    return $query[Tokens::TOKEN_PARAM] ?? null;
}

afterEach(function() {
    // Registration tokens carry a null userId, so the user-deletion cascade
    // below never reaches them — they must be pruned directly or their fixed
    // test hashes collide on the unique index on the next run.
    TokenRecord::deleteAll(['type' => Token::TYPE_REGISTER]);

    foreach (User::find()->email('*@authkit-test.example')->status(null)->all() as $user) {
        Craft::$app->getElements()->deleteElement($user, true);
    }
});

// Registration — issue
// =========================================================================

it('issues a usable, hashed, single-use registration link and emails it to an unknown address', function() {
    $email = unknownEmail();
    $mailer = new CollectingMailer();

    $issued = tokens($mailer)->issueRegistration($email);

    expect($issued)->toBeTrue()
        ->and($mailer->sent)->toHaveCount(1)
        ->and($mailer->lastRecipients())->toContain($email);

    $rawToken = rawTokenFromLink($mailer->lastLink());
    expect($rawToken)->toBeString();

    $record = TokenRecord::findOne(['tokenHash' => hash('sha256', $rawToken), 'type' => Token::TYPE_REGISTER]);
    expect($record)->not->toBeNull()
        ->and($record->userId)->toBeNull()
        ->and($record->dateConsumed)->toBeNull();

    $model = Token::fromRecord($record);
    expect($model->userId)->toBeNull()
        ->and($model->payload)->toBe(['email' => $email]);

    // The raw token must never be what is stored.
    expect(TokenRecord::findOne(['tokenHash' => $rawToken]))->toBeNull();
});

it('carries a returnUrl through to the link and payload', function() {
    $email = unknownEmail();
    $mailer = new CollectingMailer();

    tokens($mailer)->issueRegistration($email, '/welcome');

    parse_str((string)parse_url((string)$mailer->lastLink(), PHP_URL_QUERY), $query);
    expect($query['returnUrl'] ?? null)->toBe('/welcome');

    $record = TokenRecord::findOne(['tokenHash' => hash('sha256', $query[Tokens::TOKEN_PARAM]), 'type' => Token::TYPE_REGISTER]);
    $model = Token::fromRecord($record);
    expect($model->payload)->toBe(['email' => $email, 'returnUrl' => '/welcome']);
});

it('builds the registration link against the overridable registration route', function() {
    $mailer = new CollectingMailer();
    $service = tokens($mailer);
    $service->registrationRoute = 'signup/finish';

    $service->issueRegistration(unknownEmail());

    expect($mailer->lastLink())->toContain('signup/finish');
});

it('never uses Craft\'s reserved token param in the registration URL', function() {
    $mailer = new CollectingMailer();

    tokens($mailer)->issueRegistration(unknownEmail());

    parse_str((string)parse_url((string)$mailer->lastLink(), PHP_URL_QUERY), $query);
    $craftTokenParam = Craft::$app->getConfig()->getGeneral()->tokenParam;

    expect($query)->toHaveKey(Tokens::TOKEN_PARAM)
        ->and(Tokens::TOKEN_PARAM)->not->toBe($craftTokenParam)
        ->and($query)->not->toHaveKey($craftTokenParam);
});

it('refuses to issue a registration link, and mints no row, for an existing active user', function() {
    $user = tokenUser();
    $mailer = new CollectingMailer();

    $before = (int)TokenRecord::find()->count();
    $issued = tokens($mailer)->issueRegistration($user->email);

    expect($issued)->toBeFalse()
        ->and($mailer->sent)->toHaveCount(0)
        ->and((int)TokenRecord::find()->count())->toBe($before);
});

it('refuses to issue a registration link for an existing suspended user', function() {
    $user = tokenUser(User::STATUS_SUSPENDED);
    $mailer = new CollectingMailer();

    $issued = tokens($mailer)->issueRegistration($user->email);

    expect($issued)->toBeFalse()
        ->and($mailer->sent)->toHaveCount(0);
});

it('issues a registration link for an existing pending user, treating it like an unknown address', function() {
    // A pending account has not finished activating, so registration is still
    // its path: the signup link lets its holder prove mailbox possession and
    // activate. Issuance proceeds exactly as for an unknown address.
    $user = pendingTokenUser();
    $mailer = new CollectingMailer();

    $issued = tokens($mailer)->issueRegistration($user->email);

    expect($issued)->toBeTrue()
        ->and($mailer->sent)->toHaveCount(1)
        ->and($mailer->lastRecipients())->toContain($user->email);
});

it('does not issue a registration link for an empty address, without throwing', function() {
    $mailer = new CollectingMailer();

    expect(tokens($mailer)->issueRegistration('   '))->toBeFalse()
        ->and($mailer->sent)->toHaveCount(0);
});

it('refuses a malformed address through the equalized path, minting no row', function() {
    $mailer = new CollectingMailer();
    $service = tokens($mailer);

    $before = (int)TokenRecord::find()->count();

    expect($service->issueRegistration('not-an-email'))->toBeFalse()
        ->and($mailer->sent)->toHaveCount(0)
        ->and((int)TokenRecord::find()->count())->toBe($before)
        // The refusal is equalized so a malformed address is timing-indistinguishable
        // from an existing-active one.
        ->and(countEqualizerCalls(fn() => $service->issueRegistration('still@not@valid')))->toBe(1);
});

it('throttles repeated registration issues to the same address within the window', function() {
    $email = unknownEmail();
    $service = tokens();
    $service->perEmailLimit = 2;

    expect($service->issueRegistration($email))->toBeTrue()
        ->and($service->issueRegistration($email))->toBeTrue()
        ->and($service->issueRegistration($email))->toBeFalse();
});

// Registration — consume round trip + single use
// =========================================================================

it('consumes a freshly issued registration link exactly once and returns its payload', function() {
    $email = unknownEmail();
    $mailer = new CollectingMailer();
    $service = tokens($mailer);

    $service->issueRegistration($email, '/welcome');
    $rawToken = rawTokenFromLink($mailer->lastLink());

    $token = $service->consumeRegistration($rawToken);
    expect($token)->toBeInstanceOf(Token::class)
        ->and($token->type)->toBe(Token::TYPE_REGISTER)
        ->and($token->userId)->toBeNull()
        ->and($token->payload)->toBe(['email' => $email, 'returnUrl' => '/welcome'])
        ->and($token->isConsumed())->toBeTrue();

    // Single-use: the second attempt with the same token is refused.
    expect($service->consumeRegistration($rawToken))->toBeNull();
});

// Registration — consume failure matrix
// =========================================================================

it('refuses an expired registration link', function() {
    insertRegistrationToken('raw-expired-reg', expiryModifier: '-1 second');

    expect(tokens()->consumeRegistration('raw-expired-reg'))->toBeNull();
});

it('refuses an already-consumed registration link', function() {
    insertRegistrationToken('raw-consumed-reg', consumed: true);

    expect(tokens()->consumeRegistration('raw-consumed-reg'))->toBeNull();
});

it('refuses an unknown or tampered registration link', function() {
    insertRegistrationToken('the-real-reg-token');

    expect(tokens()->consumeRegistration('a-different-token'))->toBeNull();
});

it('refuses an empty registration token without throwing', function() {
    expect(tokens()->consumeRegistration('   '))->toBeNull();
});

it('does not consume a magic-link token as a registration token', function() {
    // Scoping the lookup to type=register keeps the two credential kinds from
    // being interchangeable — a login token cannot be spent to sign up.
    $user = tokenUser();
    insertToken((int)$user->id, 'a-magic-link-token');

    expect(tokens()->consumeRegistration('a-magic-link-token'))->toBeNull();
});

it('lets a before-consume handler cancel the signup without burning the token', function() {
    insertRegistrationToken('raw-cancel-reg');

    $handler = function(TokenEvent $event): void {
        $event->isValid = false;
    };
    Event::on(Tokens::class, Tokens::EVENT_BEFORE_CONSUME_TOKEN, $handler);

    try {
        expect(tokens()->consumeRegistration('raw-cancel-reg'))->toBeNull();

        $record = TokenRecord::findOne(['tokenHash' => hash('sha256', 'raw-cancel-reg'), 'type' => Token::TYPE_REGISTER]);
        expect($record->dateConsumed)->toBeNull();
    } finally {
        Event::off(Tokens::class, Tokens::EVENT_BEFORE_CONSUME_TOKEN, $handler);
    }
});

// Registration — email content
// =========================================================================

it('composes the registration email from the auth_kit_register system message', function() {
    // The subject/body render lazily inside Mailer::send(), which the collecting
    // double bypasses, so assert the message key and variables the render would
    // consume rather than the rendered output.
    $email = unknownEmail();
    $mailer = new CollectingMailer();

    tokens($mailer)->issueRegistration($email);

    $message = end($mailer->sent);
    expect($message)->not->toBeFalse()
        ->and($message->key)->toBe(Tokens::MESSAGE_KEY_REGISTER)
        ->and(array_keys($message->getTo()))->toContain($email)
        ->and($message->variables['email'] ?? null)->toBe($email)
        ->and($mailer->lastLink())->toBeString();
});

// Registration — enumeration timing parity
// =========================================================================

it('mirrors login issuance timing: the refused branch equalizes, the live branch does real work', function() {
    // A unified request endpoint dispatches an active address to issueMagicLink
    // and an unknown address to issueRegistration. Each method's send-nothing
    // branch pays exactly one fixed-cost verification, and each method's
    // send-something branch pays none (the token write + email is the real
    // cost), so the two branches stay indistinguishable by timing.
    $active = tokenUser();
    $service = tokens();

    expect(countEqualizerCalls(fn() => $service->issueRegistration($active->email)))->toBe(1)
        ->and(countEqualizerCalls(fn() => $service->issueRegistration(unknownEmail())))->toBe(0)
        ->and(countEqualizerCalls(fn() => $service->issueMagicLink(unknownEmail())))->toBe(1)
        ->and(countEqualizerCalls(fn() => $service->issueMagicLink($active->email)))->toBe(0);
});

it('equalizes the registration refusal for a suspended account but does real work for a pending one', function() {
    // Suspended stays a refusal (one equalizer call, no send); pending is a live
    // issuance (no equalizer, the token write + email is the real cost), so both
    // stay indistinguishable by timing from, respectively, the active-refusal
    // and unknown-address branches of a unified endpoint.
    $suspended = tokenUser(User::STATUS_SUSPENDED);
    $pending = pendingTokenUser();
    $service = tokens();

    expect(countEqualizerCalls(fn() => $service->issueRegistration($suspended->email)))->toBe(1)
        ->and(countEqualizerCalls(fn() => $service->issueRegistration($pending->email)))->toBe(0);
});
