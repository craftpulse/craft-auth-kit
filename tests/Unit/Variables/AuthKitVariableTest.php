<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Smoke tests for the `craft.authKit` Twig variable: that it is registered and
 * renders, and that its passwordless helpers behave for a guest.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craftpulse\authkit\variables\AuthKitVariable;

it('registers craft.authKit and renders its passkey check for a guest', function() {
    Craft::$app->getUser()->setIdentity(null);

    $out = Craft::$app->getView()->renderString('{{ craft.authKit.hasPasskeys() ? "yes" : "no" }}');

    expect(trim($out))->toBe('no');
});

it('exposes the published webauthn client url', function() {
    $url = (new AuthKitVariable())->webauthnJsUrl();

    expect($url)->toContain('authkit-webauthn.js');
});

it('returns no passkeys for a guest', function() {
    Craft::$app->getUser()->setIdentity(null);

    expect((new AuthKitVariable())->passkeys())->toBe([])
        ->and((new AuthKitVariable())->hasPasskeys())->toBeFalse();
});
