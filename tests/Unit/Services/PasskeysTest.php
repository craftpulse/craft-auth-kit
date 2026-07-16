<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
 *
 * Tests for the passkeys service: the recent-auth gate (the security-relevant
 * boundary Auth Kit owns) and the delegations to core's Auth service. The
 * WebAuthn ceremonies themselves are core's, and are not re-tested here.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craft\elements\User;
use craft\helpers\StringHelper;
use craftpulse\authkit\AuthKit;
use craftpulse\authkit\services\Passkeys;
use yii\web\ForbiddenHttpException;

function passkeysService(): Passkeys
{
    return AuthKit::getInstance()->getPasskeys();
}

function passkeyUser(): User
{
    $unique = str_replace('-', '', StringHelper::UUID());
    $user = new User();
    $user->username = "pk-{$unique}@authkit-test.example";
    $user->email = "pk-{$unique}@authkit-test.example";

    if (!Craft::$app->getElements()->saveElement($user)) {
        throw new RuntimeException('Could not save passkey test user.');
    }

    Craft::$app->getUsers()->activateUser($user);

    return Craft::$app->getUsers()->getUserById((int)$user->id);
}

afterEach(function() {
    Craft::$app->getSession()->remove(Passkeys::SESSION_RECENT_AUTH_KEY);

    foreach (User::find()->email('*@authkit-test.example')->status(null)->all() as $user) {
        Craft::$app->getElements()->deleteElement($user, true);
    }
});

// Recent-auth gate
// =========================================================================

it('reports no recent auth when nothing has been stamped', function() {
    Craft::$app->getSession()->remove(Passkeys::SESSION_RECENT_AUTH_KEY);

    expect(passkeysService()->hasRecentAuth())->toBeFalse();
});

it('reports recent auth immediately after stamping', function() {
    $service = passkeysService();
    $service->stampRecentAuth();

    expect($service->hasRecentAuth())->toBeTrue();
});

it('treats a stale stamp as no longer recent', function() {
    Craft::$app->getSession()->set(Passkeys::SESSION_RECENT_AUTH_KEY, time() - 1000);
    $service = passkeysService();
    $service->recentAuthDuration = 300;

    expect($service->hasRecentAuth())->toBeFalse();
});

it('honours an explicit window argument over the configured duration', function() {
    Craft::$app->getSession()->set(Passkeys::SESSION_RECENT_AUTH_KEY, time() - 120);
    $service = passkeysService();

    expect($service->hasRecentAuth(60))->toBeFalse()
        ->and($service->hasRecentAuth(600))->toBeTrue();
});

// Delegation to core Auth
// =========================================================================

it('reports a fresh user as having no passkeys', function() {
    $user = passkeyUser();

    expect(passkeysService()->hasPasskeys($user))->toBeFalse()
        ->and(passkeysService()->getPasskeys($user))->toBe([]);
});

it('reports false when deleting a nonexistent passkey', function() {
    // Core's delete is a silent no-op for an unknown UID; the boolean return
    // is what lets consumers keep audit trails factual.
    $user = passkeyUser();
    $service = passkeysService();
    $service->stampRecentAuth();

    expect($service->deletePasskey($user, StringHelper::UUID()))->toBeFalse()
        ->and($service->hasPasskeys($user))->toBeFalse();
});

// Recent-auth enforcement
// =========================================================================

it('refuses to delete a passkey when the session has not authenticated recently', function() {
    // The gate is enforced inside the service, not just advised in docs — a
    // consumer that forgets its controller-side check cannot ship an ungated
    // deletion path.
    $user = passkeyUser();

    passkeysService()->deletePasskey($user, StringHelper::UUID());
})->throws(ForbiddenHttpException::class);

it('refuses to verify a passkey creation when the session has not authenticated recently', function() {
    passkeysService()->verifyCreation('{}');
})->throws(ForbiddenHttpException::class);

it('honors a caller-supplied recent-auth window on the mutating gate', function() {
    // Stamped 120s ago: inside the 300s default, outside a caller's stricter
    // 60s window — per-call windows let each consumer keep its own policy
    // without mutating the shared service default.
    Craft::$app->getSession()->set(Passkeys::SESSION_RECENT_AUTH_KEY, time() - 120);
    $user = passkeyUser();

    passkeysService()->deletePasskey($user, StringHelper::UUID(), 60);
})->throws(ForbiddenHttpException::class);

it('produces serialized creation options for a user', function() {
    $user = passkeyUser();

    $options = passkeysService()->getCreationOptions($user);

    expect($options)->toBeString()
        ->and($options)->toContain('challenge');
});
