<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Regression tests for the project config half of the plugin-to-module
 * adoption: the `plugins.auth-kit` entry the plugin era registered has to be
 * gone, durably, the moment `Adoption::adoptFromPlugin()` returns. An entry
 * left behind is not inert — the next external apply reads it as a plugin that
 * still needs installing, which reinstates the registration the adoption just
 * shed.
 *
 * Every assertion here reads the *stored* config: the `projectconfig` table and
 * the YAML on disk, never `ProjectConfig::get()`. `get()` reads the in-memory
 * working copy, which the removal mutates whether or not anything was ever
 * written down — so a working-copy assertion passes either way, and that is
 * exactly why an entry surviving in YAML alone went unnoticed through two
 * releases.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craft\db\Query;
use craft\db\Table as CraftTable;
use craft\helpers\Db;
use craft\helpers\FileHelper;
use craft\services\ProjectConfig;
use craftpulse\authkit\AuthKit;
use craftpulse\authkit\migrations\Adoption;
use Symfony\Component\Yaml\Yaml;
use yii\base\Event;

/**
 * @var string A second plugin's handle, used to prove every write the adoption
 * issues is scoped to Auth Kit's own registration.
 */
const AUTHKIT_FOREIGN_HANDLE = 'auth-kit-test-consumer';

/**
 * Returns the project config path a plugin registers itself under.
 *
 * @param string $handle the plugin handle
 * @return string
 */
function authKitPluginConfigPath(string $handle = AuthKit::ID): string
{
    return ProjectConfig::PATH_PLUGINS . '.' . $handle;
}

/**
 * Seeds a plugin-era row in the `plugins` table.
 *
 * @param string $handle the plugin handle
 */
function authKitSeedPluginRow(string $handle = AuthKit::ID): void
{
    Db::insert(CraftTable::PLUGINS, [
        'handle' => $handle,
        'version' => '1.6.2',
        'schemaVersion' => '1.3.0',
        'installDate' => Db::prepareDateForDb(new DateTime()),
    ], db: Craft::$app->getDb());
}

/**
 * Seeds a plugin-era project config entry and, unlike a bare `set()`, persists
 * it — so a test asserting on the stored config is asserting against a removal
 * rather than against an entry that was never written in the first place.
 *
 * @param string $handle the plugin handle
 */
function authKitSeedStoredConfigEntry(string $handle = AuthKit::ID): void
{
    $projectConfig = Craft::$app->getProjectConfig();

    $muteEvents = $projectConfig->muteEvents;
    $readOnly = $projectConfig->readOnly;
    $projectConfig->muteEvents = true;
    $projectConfig->readOnly = false;

    try {
        $projectConfig->set(authKitPluginConfigPath($handle), [
            'edition' => 'standard',
            'enabled' => true,
            'schemaVersion' => '1.3.0',
        ]);
        $projectConfig->flush();
    } finally {
        $projectConfig->readOnly = $readOnly;
        $projectConfig->muteEvents = $muteEvents;
    }
}

/**
 * Seeds an external (YAML) config carrying a plugin-era entry the loaded config
 * does not have: the state a deploy leaves behind when the YAML still names the
 * plugin and the database no longer does.
 */
function authKitSeedExternalOnlyConfigEntry(): void
{
    $projectConfig = Craft::$app->getProjectConfig();
    $file = Craft::$app->getPath()->getProjectConfigFilePath();

    FileHelper::writeToFile($file, Yaml::dump([
        ProjectConfig::PATH_DATE_MODIFIED => $projectConfig->get(ProjectConfig::PATH_DATE_MODIFIED),
        ProjectConfig::PATH_PLUGINS => [
            AuthKit::ID => [
                'edition' => 'standard',
                'enabled' => true,
                'schemaVersion' => '1.3.0',
            ],
        ],
    ], 20, 2));

    // Drop the memoized external config and file list so the seeded file is
    // what the service reads next.
    $projectConfig->reset();
}

/**
 * Returns the stored project config paths under a plugin's entry. This is the
 * persisted config, straight out of the database, not the loaded working copy.
 *
 * @param string $handle the plugin handle
 * @return string[]
 */
function authKitStoredConfigPaths(string $handle = AuthKit::ID): array
{
    /** @var string[] $paths */
    $paths = (new Query())
        ->select(['path'])
        ->from([CraftTable::PROJECTCONFIG])
        ->where(['or',
            ['path' => authKitPluginConfigPath($handle)],
            ['like', 'path', authKitPluginConfigPath($handle) . '.%', false],
        ])
        ->column(Craft::$app->getDb());

    sort($paths);

    return $paths;
}

/**
 * Returns the external project config as it currently sits on disk.
 *
 * @return array<string, mixed>
 */
function authKitExternalConfigOnDisk(): array
{
    $file = Craft::$app->getPath()->getProjectConfigFilePath();

    if (!is_file($file)) {
        return [];
    }

    return (array)Yaml::parse((string)file_get_contents($file));
}

/**
 * Returns whether the `plugins` table still carries a row for the given handle.
 *
 * @param string $handle the plugin handle
 * @return bool
 */
function authKitPluginRowExists(string $handle = AuthKit::ID): bool
{
    return (new Query())
        ->from([CraftTable::PLUGINS])
        ->where(['handle' => $handle])
        ->exists(Craft::$app->getDb());
}

beforeEach(function() {
    $projectConfig = Craft::$app->getProjectConfig();

    $this->configVersion = Craft::$app->getInfo()->configVersion;
    $this->writeYamlAutomatically = $projectConfig->writeYamlAutomatically;
    $this->externalConfigExisted = $projectConfig->getDoesExternalConfigExist();

    // Only the external-config test cares about YAML; the rest assert on the
    // database and have no business rewriting the install's config files.
    $projectConfig->writeYamlAutomatically = false;
});

afterEach(function() {
    $projectConfig = Craft::$app->getProjectConfig();
    $projectConfig->writeYamlAutomatically = $this->writeYamlAutomatically;

    $configPath = Craft::$app->getPath()->getProjectConfigPath(false);

    if (!$this->externalConfigExisted && is_dir($configPath)) {
        FileHelper::clearDirectory($configPath, ['except' => ['.*', '.*/']]);
    }

    // `flush()` rerolls the memoized configVersion; RefreshesDatabase rolls the
    // stored one back moments from now, and `ProjectConfig::_acquireLock()`
    // throws StaleResourceException on the next write when the two disagree.
    Craft::$app->getInfo()->configVersion = $this->configVersion;

    // Drop the memoized internal config, external config, and file list so no
    // seeded state leaks into the next test.
    $projectConfig->reset();
});

it('writes nothing on an install that never had the plugin', function() {
    // tests/Bootstrap.php already adopted, so this is the state a genuinely
    // fresh install presents: no plugins row, no stored config entry.
    expect(authKitPluginRowExists())->toBeFalse();
    expect(authKitStoredConfigPaths())->toBe([]);

    expect(fn() => Adoption::adoptFromPlugin())->not->toThrow(Throwable::class);

    expect(authKitPluginRowExists())->toBeFalse();
    expect(authKitStoredConfigPaths())->toBe([]);

    // A clean no-op, not merely a quiet one: `saveModifiedConfigData()` is the
    // only thing that rerolls configVersion and `flush()` is the only way to
    // reach it, so an unchanged version proves nothing was written at all.
    expect(Craft::$app->getInfo()->configVersion)->toBe($this->configVersion);
});

it('removes a plugin-era entry that survives only in the external config', function() {
    $projectConfig = Craft::$app->getProjectConfig();
    $projectConfig->writeYamlAutomatically = true;

    authKitSeedExternalOnlyConfigEntry();

    // The entry exists in the external config alone. Left behind there, the next
    // external apply reads it as a plugin that still needs installing and
    // restores the registration the adoption just shed.
    expect($projectConfig->get(authKitPluginConfigPath()))->toBeNull();
    expect($projectConfig->get(authKitPluginConfigPath(), true))->not->toBeNull();

    Adoption::adoptFromPlugin();

    // Asserted against the YAML on disk. `get()` would report the entry gone
    // either way: the loaded config never had it.
    $external = authKitExternalConfigOnDisk();
    expect($external[ProjectConfig::PATH_PLUGINS][AuthKit::ID] ?? null)->toBeNull();

    $projectConfig->reset();
    expect($projectConfig->get(authKitPluginConfigPath(), true))->toBeNull();
});

it('persists the removal without a request lifecycle', function() {
    authKitSeedPluginRow();
    authKitSeedStoredConfigEntry();

    // The seeded entry really is in the stored config, not just the loaded
    // working copy, so its absence below is a removal.
    expect(authKitStoredConfigPaths())->not->toBe([]);

    Adoption::adoptFromPlugin();

    // Asserted the moment the adoption returns: no EVENT_AFTER_REQUEST, no
    // simulated request end. A console process that exits here, or a harness
    // that never runs a request lifecycle, must still find the entry gone.
    expect(authKitStoredConfigPaths())->toBe([]);
    expect(authKitPluginRowExists())->toBeFalse();
});

it('adopts a read-only install and restores both flags it lifted', function() {
    authKitSeedPluginRow();
    authKitSeedStoredConfigEntry();

    $projectConfig = Craft::$app->getProjectConfig();
    $readOnly = $projectConfig->readOnly;

    // What `allowAdminChanges => false` boots the service with, per
    // craft\helpers\App::projectConfigConfig().
    $projectConfig->readOnly = true;

    try {
        Adoption::adoptFromPlugin();

        // Asserted before the restore below, which would otherwise be the thing
        // putting the flag back.
        expect($projectConfig->readOnly)->toBeTrue();
        expect($projectConfig->muteEvents)->toBeFalse();
    } finally {
        $projectConfig->readOnly = $readOnly;
    }

    // The lift is what Craft's own Plugins::uninstallPlugin() does, and without
    // it `set()` throws NotSupportedException and fails the consumer's upgrade.
    expect(authKitStoredConfigPaths())->toBe([]);
});

it('mutes project config item events across the removal and the flush', function() {
    authKitSeedPluginRow();
    authKitSeedStoredConfigEntry();

    $names = [
        ProjectConfig::EVENT_ADD_ITEM,
        ProjectConfig::EVENT_UPDATE_ITEM,
        ProjectConfig::EVENT_REMOVE_ITEM,
    ];

    $fired = [];
    $record = function() use (&$fired) {
        $fired[] = true;
    };

    foreach ($names as $name) {
        Event::on(ProjectConfig::class, $name, $record);
    }

    try {
        Adoption::adoptFromPlugin();
    } finally {
        foreach ($names as $name) {
            Event::off(ProjectConfig::class, $name, $record);
        }
    }

    // Nothing may react to the removal as if a real uninstall were happening,
    // and the flush must not re-fire what the removal muted.
    expect($fired)->toBe([]);
});

it('deletes the plugins row only after the project config entry is gone', function() {
    authKitSeedPluginRow();

    $projectConfig = Craft::$app->getProjectConfig();

    Craft::$app->set('projectConfig', new class() extends ProjectConfig {
        /**
         * @inheritdoc
         */
        public function get(?string $path = null, bool $getFromExternalConfig = false): mixed
        {
            throw new RuntimeException('Project config unavailable');
        }
    });

    try {
        expect(fn() => Adoption::adoptFromPlugin())->toThrow(RuntimeException::class);
    } finally {
        Craft::$app->set('projectConfig', $projectConfig);
    }

    // The registration row outlived the failure, so the next adoption call
    // retries the whole removal instead of leaving a `plugins` table with no row
    // and a project config that still names the plugin.
    expect(authKitPluginRowExists())->toBeTrue();
});

it('writes nothing on a repeat run', function() {
    authKitSeedPluginRow();
    authKitSeedStoredConfigEntry();

    Adoption::adoptFromPlugin();

    expect(authKitStoredConfigPaths())->toBe([]);
    expect(authKitPluginRowExists())->toBeFalse();

    $configVersion = Craft::$app->getInfo()->configVersion;

    expect(fn() => Adoption::adoptFromPlugin())->not->toThrow(Throwable::class);

    // A clean no-op, not merely a quiet one: `saveModifiedConfigData()` is the
    // only thing that rerolls configVersion and `flush()` is the only way to
    // reach it, so an unchanged version proves the second run wrote nothing.
    expect(Craft::$app->getInfo()->configVersion)->toBe($configVersion);
    expect(authKitStoredConfigPaths())->toBe([]);
    expect(authKitPluginRowExists())->toBeFalse();
});

it('touches nothing outside its own registration', function() {
    authKitSeedPluginRow();
    authKitSeedStoredConfigEntry();
    authKitSeedPluginRow(AUTHKIT_FOREIGN_HANDLE);
    authKitSeedStoredConfigEntry(AUTHKIT_FOREIGN_HANDLE);

    Adoption::adoptFromPlugin();

    expect(authKitStoredConfigPaths())->toBe([]);
    expect(authKitPluginRowExists())->toBeFalse();

    // Every write is scoped to Auth Kit's own handle.
    expect(authKitStoredConfigPaths(AUTHKIT_FOREIGN_HANDLE))->not->toBe([]);
    expect(authKitPluginRowExists(AUTHKIT_FOREIGN_HANDLE))->toBeTrue();
});
