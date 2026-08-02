<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Regression tests for the plugin-to-module adoption helper, which is the
 * whole upgrade story a consumer ships as a one-line migration. The failure
 * modes it guards against are all silent: a migration history that isn't
 * carried onto the module track replays schema work; a `plugins` row or a
 * `plugins.auth-kit` project config entry left behind keeps Craft treating a
 * module as an installed plugin; and a helper that isn't idempotent breaks the
 * second consumer to run it on a shared install.
 *
 * `authkit_tokens` must survive every one of these, because the one thing the
 * adoption must never do is take the token store with it.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craft\db\Query;
use craft\db\Table as CraftTable;
use craft\helpers\Db;
use craftpulse\authkit\AuthKit;
use craftpulse\authkit\db\Table;
use craftpulse\authkit\migrations\Adoption;

/**
 * Returns the migration names currently recorded on the given track.
 *
 * @param string $track the migration track to read
 * @return string[]
 */
function authKitTrackHistory(string $track): array
{
    /** @var string[] $names */
    $names = (new Query())
        ->select(['name'])
        ->from([CraftTable::MIGRATIONS])
        ->where(['track' => $track])
        ->column(Craft::$app->getDb());

    sort($names);

    return $names;
}

it('leaves the module track carrying every migration after the bootstrap adoption', function() {
    // tests/Bootstrap.php performs the real consumer wiring (register, then
    // adoptFromPlugin) before any test runs, so this is the post-adoption
    // steady state every other test in the suite depends on.
    $history = authKitTrackHistory(Adoption::MODULE_TRACK);

    expect($history)->toContain('m260617_000000_Install');
    expect(count($history))->toBe(count(AuthKit::getInstance()->getMigrator()->getMigrationHistory()));
});

it('leaves no plugin-track history, no plugins row, and no project config entry', function() {
    expect(authKitTrackHistory(Adoption::PLUGIN_TRACK))->toBe([]);

    $pluginRow = (new Query())
        ->from([CraftTable::PLUGINS])
        ->where(['handle' => AuthKit::ID])
        ->exists(Craft::$app->getDb());

    expect($pluginRow)->toBeFalse();

    $projectConfig = Craft::$app->getProjectConfig();

    expect($projectConfig->get('plugins.' . AuthKit::ID))->toBeNull();
    expect($projectConfig->get('plugins.' . AuthKit::ID, true))->toBeNull();
});

it('carries a plugin-era history onto the module track and clears the plugin track', function() {
    $db = Craft::$app->getDb();

    // Rewind to the plugin era: the module track is how the plugin era never
    // recorded anything, and the plugin track carries the bare `Install` name
    // Craft's plugin installer uses plus the dated deltas. The tokens table
    // stays in place, which is what tells the helper the install migration was
    // already applied. These are plain DML writes, so RefreshesDatabase rolls
    // them back with the rest of the test.
    $moduleHistory = authKitTrackHistory(Adoption::MODULE_TRACK);
    Db::delete(CraftTable::MIGRATIONS, ['track' => Adoption::MODULE_TRACK], db: $db);

    foreach (['Install', 'm260711_000001_MakeTokenUserIdNullable', 'm260716_000001_AddTokenOrigin', 'm260718_000001_AddTokenSubject'] as $name) {
        Db::insert(CraftTable::MIGRATIONS, [
            'track' => Adoption::PLUGIN_TRACK,
            'name' => $name,
            'applyTime' => Db::prepareDateForDb(new DateTime()),
        ], db: $db);
    }

    Adoption::adoptFromPlugin();

    // The bare `Install` name is deliberately NOT copied across: it is not a
    // name the module track's migrator would ever discover. Its dated wrapper
    // stands in for it, marked because the tokens table already exists.
    expect(authKitTrackHistory(Adoption::MODULE_TRACK))->toBe($moduleHistory);
    expect(authKitTrackHistory(Adoption::PLUGIN_TRACK))->toBe([]);
    expect($db->tableExists(Table::TOKENS))->toBeTrue();
});

it('removes a leftover plugins row without touching the token store', function() {
    $db = Craft::$app->getDb();

    Db::insert(CraftTable::PLUGINS, [
        'handle' => AuthKit::ID,
        'version' => '1.6.2',
        'schemaVersion' => '1.3.0',
        'installDate' => Db::prepareDateForDb(new DateTime()),
    ], db: $db);

    Adoption::adoptFromPlugin();

    $pluginRow = (new Query())
        ->from([CraftTable::PLUGINS])
        ->where(['handle' => AuthKit::ID])
        ->exists($db);

    expect($pluginRow)->toBeFalse();
    expect($db->tableExists(Table::TOKENS))->toBeTrue();
});

it('is a no-op when re-run on an install that is already adopted', function() {
    $db = Craft::$app->getDb();

    $moduleHistory = authKitTrackHistory(Adoption::MODULE_TRACK);

    // Twice, because a consumer install with both Warp and Warden ships two
    // adoption migrations and the second must find nothing left to do.
    Adoption::adoptFromPlugin();
    Adoption::adoptFromPlugin();

    expect(authKitTrackHistory(Adoption::MODULE_TRACK))->toBe($moduleHistory);
    expect(authKitTrackHistory(Adoption::PLUGIN_TRACK))->toBe([]);
    expect($db->tableExists(Table::TOKENS))->toBeTrue();
});
