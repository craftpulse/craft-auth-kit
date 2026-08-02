<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Regression tests for the module registration contract consumers depend on.
 * Every consuming plugin calls `AuthKit::register()` from its own `init()`,
 * so on an install carrying more than one of them the call happens repeatedly
 * against an application that already has the module: it must return the same
 * instance rather than replace a live one, or services swapped mid-request
 * would silently lose registered sinks and validators.
 *
 * The component fill-in is covered here too, because it is what makes the
 * documented `config/app.php` tuning safe. Yii's `setComponents()` overwrites
 * rather than merges, so a partial override must leave the services it did
 * not mention intact.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craftpulse\authkit\AuthKit;
use craftpulse\authkit\services\Audit;
use craftpulse\authkit\services\Passkeys;
use craftpulse\authkit\services\Passwords;
use craftpulse\authkit\services\Tokens;

it('is registered on the application under its module id', function() {
    expect(Craft::$app->getModule(AuthKit::ID))->toBeInstanceOf(AuthKit::class);
});

it('returns the same instance on repeated registration, as two consumers would', function() {
    $first = AuthKit::register();
    $second = AuthKit::register();

    expect($first)->toBe($second);
    expect(AuthKit::getInstance())->toBe($first);
    expect(AuthKit::$plugin)->toBe($first);
});

it('does not appear in Craft as an installed or even available plugin', function() {
    $plugins = Craft::$app->getPlugins();

    expect($plugins->isPluginInstalled(AuthKit::ID))->toBeFalse();
    expect($plugins->isPluginEnabled(AuthKit::ID))->toBeFalse();
    expect($plugins->getPlugin(AuthKit::ID))->toBeNull();
});

it('exposes every service through its typed accessor', function() {
    $authKit = AuthKit::getInstance();

    expect($authKit->getAudit())->toBeInstanceOf(Audit::class);
    expect($authKit->getPasskeys())->toBeInstanceOf(Passkeys::class);
    expect($authKit->getPasswords())->toBeInstanceOf(Passwords::class);
    expect($authKit->getTokens())->toBeInstanceOf(Tokens::class);
});

it('fills in the services a partial config/app.php override leaves out', function() {
    // Exactly what Yii hands the module when an install declares only one
    // component under `modules.auth-kit` in config/app.php.
    $module = new AuthKit('auth-kit-fixture', Craft::$app, [
        'components' => [
            'tokens' => ['class' => Tokens::class, 'tokenTtl' => 600],
        ],
    ]);

    // The override survives...
    expect($module->getTokens()->tokenTtl)->toBe(600);

    // ...and the three services it never mentioned are still there.
    expect($module->getAudit())->toBeInstanceOf(Audit::class);
    expect($module->getPasskeys())->toBeInstanceOf(Passkeys::class);
    expect($module->getPasswords())->toBeInstanceOf(Passwords::class);

    // A module built under any other id must not displace the singleton the
    // whole ecosystem reaches through.
    expect(AuthKit::$plugin)->not->toBe($module);
    expect(AuthKit::getInstance())->not->toBe($module);
});

it('resolves its own Tokens service, never Craft\'s same-named one', function() {
    // The module's parent is the Craft application, whose own `tokens`
    // component is craft\services\Tokens. Yii's Module::get()/has() both fall
    // back to the parent, so any gap in Auth Kit's own component definitions
    // resolves Craft's service instead, silently and with no error.
    $tokens = AuthKit::getInstance()->getTokens();

    expect($tokens)->toBeInstanceOf(Tokens::class);
    expect($tokens)->not->toBeInstanceOf(\craft\services\Tokens::class);
});

it('runs its migrations on the module track, not a plugin track', function() {
    expect(AuthKit::getInstance()->getMigrator()->track)->toBe('module:auth-kit');
});
