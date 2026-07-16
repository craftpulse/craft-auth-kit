<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
 *
 * SLOW-MODE test matrix for per-consumer issuance scoping (1.4.0). Two
 * plugins (e.g. Warden and Warp) share one token store; the `origin` label
 * is the isolation boundary between them: a token issued by one consumer
 * must never be honored at another consumer's endpoint, per-origin OTPs must
 * not supersede each other, and per-issuance options (route, ttl, digits,
 * attempts, throttle) must override the shared service defaults so the
 * last-loaded plugin can no longer clobber the first's configuration.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craft\elements\User;
use craft\helpers\StringHelper;
use craftpulse\authkit\records\Token as TokenRecord;
use craftpulse\authkit\services\Tokens;
use craftpulse\authkit\tests\Support\CollectingMailer;

/**
 * Local helpers — deliberately self-contained so this file never depends on
 * another test file having been loaded first.
 */
function originTokens(?CollectingMailer $mailer = null): Tokens
{
    return new Tokens(['mailer' => $mailer ?? new CollectingMailer()]);
}

function originTokenUser(): User
{
    $unique = str_replace('-', '', StringHelper::UUID());
    $user = new User();
    $user->username = "tko-{$unique}@authkit-test.example";
    $user->email = "tko-{$unique}@authkit-test.example";

    if (!Craft::$app->getElements()->saveElement($user)) {
        throw new RuntimeException('Could not save origin test user.');
    }

    Craft::$app->getUsers()->activateUser($user);

    return Craft::$app->getUsers()->getUserById((int)$user->id);
}

afterEach(function() {
    foreach (User::find()->email('tko-*@authkit-test.example')->status(null)->all() as $user) {
        Craft::$app->getElements()->deleteElement($user, true);
    }
});

// Magic link — origin scoping
// =========================================================================

it('round-trips a magic link within one origin and honors the route override', function() {
    $mailer = new CollectingMailer();
    $service = originTokens($mailer);
    $user = originTokenUser();

    expect($service->issueMagicLink($user->email, null, [
        'origin' => 'warden',
        'route' => 'warden/magic-link/verify',
    ]))->toBeTrue();

    $link = (string)$mailer->lastLink();
    expect($link)->toContain('warden/magic-link/verify');

    parse_str((string)parse_url($link, PHP_URL_QUERY), $query);
    $raw = (string)($query['mlToken'] ?? '');

    $consumed = $service->consumeMagicLink($raw, 'warden');

    expect($consumed?->id)->toBe((int)$user->id);
});

it('refuses a magic link at another origin and leaves it unburned for its own', function() {
    $mailer = new CollectingMailer();
    $service = originTokens($mailer);
    $user = originTokenUser();

    $service->issueMagicLink($user->email, null, ['origin' => 'warden']);

    parse_str((string)parse_url((string)$mailer->lastLink(), PHP_URL_QUERY), $query);
    $raw = (string)($query['mlToken'] ?? '');

    // The wrong consumer must not log anyone in — and must not burn the
    // token either, or a probe at the wrong endpoint could deny the real one.
    expect($service->consumeMagicLink($raw, 'warp'))->toBeNull();

    $record = TokenRecord::findOne(['tokenHash' => hash('sha256', $raw)]);

    expect($record)->not->toBeNull()
        ->and($record->dateConsumed)->toBeNull();

    // The rightful origin still consumes it.
    expect($service->consumeMagicLink($raw, 'warden')?->id)->toBe((int)$user->id);
});

it('scopes strictly: a legacy origin-less token is not honored by an origin-passing consumer, and vice versa', function() {
    $mailer = new CollectingMailer();
    $service = originTokens($mailer);
    $user = originTokenUser();

    // Legacy issuance (no origin).
    $service->issueMagicLink($user->email);
    parse_str((string)parse_url((string)$mailer->lastLink(), PHP_URL_QUERY), $query);
    $legacyRaw = (string)($query['mlToken'] ?? '');

    expect($service->consumeMagicLink($legacyRaw, 'warden'))->toBeNull()
        ->and($service->consumeMagicLink($legacyRaw)?->id)->toBe((int)$user->id);

    // Origin issuance is equally invisible to a legacy (origin-less) consume.
    $service->issueMagicLink($user->email, null, ['origin' => 'warden']);
    parse_str((string)parse_url((string)$mailer->lastLink(), PHP_URL_QUERY), $query);
    $scopedRaw = (string)($query['mlToken'] ?? '');

    expect($service->consumeMagicLink($scopedRaw))->toBeNull()
        ->and($service->consumeMagicLink($scopedRaw, 'warden')?->id)->toBe((int)$user->id);
});

// OTP — origin scoping
// =========================================================================

it('keeps per-origin OTPs independent: no cross-origin supersede, no cross-origin consume', function() {
    $mailer = new CollectingMailer();
    $service = originTokens($mailer);
    $user = originTokenUser();

    expect($service->issueOtp($user->email, ['origin' => 'warp']))->toBeTrue();
    $warpCode = (string)$mailer->lastCode();

    // Warden's later issuance must not burn Warp's live code.
    expect($service->issueOtp($user->email, ['origin' => 'warden']))->toBeTrue();
    $wardenCode = (string)$mailer->lastCode();

    // Warp's code no longer works at Warden's endpoint...
    expect($service->consumeOtp($user->email, $warpCode, 'warden'))->toBeNull();

    // ...but still works at Warp's own, and Warden's at Warden's.
    expect($service->consumeOtp($user->email, $warpCode, 'warp')?->id)->toBe((int)$user->id)
        ->and($service->consumeOtp($user->email, $wardenCode, 'warden')?->id)->toBe((int)$user->id);
});

it('honors per-issuance OTP digits and attempt caps', function() {
    $mailer = new CollectingMailer();
    $service = originTokens($mailer);
    $user = originTokenUser();

    $service->issueOtp($user->email, ['origin' => 'warden', 'digits' => 8, 'maxAttempts' => 2]);

    $code = (string)$mailer->lastCode();
    $record = TokenRecord::findOne(['userId' => $user->id, 'dateConsumed' => null]);

    expect(strlen($code))->toBe(8)
        ->and($record?->maxAttempts)->toBe(2);
});

// Per-issuance ttl and throttle
// =========================================================================

it('honors a per-issuance ttl override', function() {
    $mailer = new CollectingMailer();
    $service = originTokens($mailer);
    $user = originTokenUser();

    $service->issueMagicLink($user->email, null, ['origin' => 'warden', 'ttl' => 60]);

    $record = TokenRecord::findOne(['userId' => $user->id]);
    $expiry = new DateTime((string)$record->expiryDate, new DateTimeZone('UTC'));
    $delta = $expiry->getTimestamp() - time();

    expect($delta)->toBeGreaterThan(30)
        ->and($delta)->toBeLessThanOrEqual(61);
});

it('throttles per origin: one consumer exhausting its budget does not starve another', function() {
    $service = originTokens();
    $user = originTokenUser();

    $options = ['origin' => 'warden', 'perEmailLimit' => 2, 'perEmailWindow' => 300];

    expect($service->issueMagicLink($user->email, null, $options))->toBeTrue()
        ->and($service->issueMagicLink($user->email, null, $options))->toBeTrue()
        ->and($service->issueMagicLink($user->email, null, $options))->toBeFalse();

    // A different origin has its own bucket for the same address.
    expect($service->issueMagicLink($user->email, null, ['origin' => 'warp', 'perEmailLimit' => 2, 'perEmailWindow' => 300]))->toBeTrue();
});

it('rejects unknown issuance options loudly', function() {
    originTokens()->issueMagicLink('nobody@authkit-test.example', null, ['orgin' => 'warden']);
})->throws(InvalidArgumentException::class);

// Registration — origin scoping
// =========================================================================

it('scopes registration tokens by origin with a route override', function() {
    $mailer = new CollectingMailer();
    $service = originTokens($mailer);
    $email = 'reg-' . str_replace('-', '', StringHelper::UUID()) . '@authkit-test.example';

    expect($service->issueRegistration($email, null, [
        'origin' => 'warp',
        'route' => 'warp/auth/verify-registration',
    ]))->toBeTrue();

    $link = (string)$mailer->lastLink();
    expect($link)->toContain('warp/auth/verify-registration');

    parse_str((string)parse_url($link, PHP_URL_QUERY), $query);
    $raw = (string)($query['mlToken'] ?? '');

    // Wrong origin: refused, unburned. Right origin: burned token returned.
    expect($service->consumeRegistration($raw, 'warden'))->toBeNull();

    $token = $service->consumeRegistration($raw, 'warp');

    expect($token)->not->toBeNull()
        ->and($token->payload['email'] ?? null)->toBe($email);
});
