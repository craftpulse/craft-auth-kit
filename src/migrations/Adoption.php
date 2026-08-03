<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\migrations;

use Craft;
use craft\db\Query;
use craft\db\Table as CraftTable;
use craft\helpers\Db;
use craft\services\ProjectConfig;
use craftpulse\authkit\AuthKit;
use craftpulse\authkit\db\Table;

/**
 * Adoption converts a plugin-era Auth Kit install (1.6.x and earlier, composer
 * type `craft-plugin`) into the module-era layout (1.7.0+, composer type
 * `library`), and is the whole upgrade story for consumers: their upgrade
 * migration is the one-liner `Adoption::adoptFromPlugin();`.
 *
 * What one call does, in order:
 *
 * 1. Migration history: marks Auth Kit's already-applied migrations as applied
 *    on the module track (`module:auth-kit`), so the module's migrator never
 *    replays work the plugin era already did. The plugin track
 *    (`plugin:auth-kit`) is the ground truth for the dated migrations; the
 *    presence of the tokens table is the ground truth for the install
 *    migration (plugin installs recorded it under the bare name `Install`,
 *    which maps to the module track's `m260617_000000_Install`). The orphaned
 *    plugin-track rows are then deleted.
 * 2. Plugin registration: removes the `plugins.auth-kit` project config entry
 *    with project config events muted and read-only temporarily lifted, then
 *    the `auth-kit` row from the `plugins` table. Auth Kit's own tables are
 *    never touched — this is deliberately NOT `Plugins::uninstallPlugin()`,
 *    which would run `Install::safeDown()` and drop the token store.
 * 3. Catch-up: runs the module migrator's `up()`, applying anything genuinely
 *    pending — everything on a fresh install, only unapplied deltas on a
 *    partially-updated plugin-era install, nothing when already current.
 *
 * Every step is idempotent and a no-op where its work is already done, so the
 * call is safe on an install that never had the plugin (it degrades to plain
 * `up()`), safe to re-run, and safe for multiple consumers: when Warp and
 * Warden both ship an adoption migration on the same install, whichever runs
 * first does the work and the other finds nothing left to do.
 *
 * @author CraftPulse
 * @since 1.7.0
 */
final class Adoption
{
    // Const Properties
    // =========================================================================

    /**
     * @var string The migration track plugin-era installs recorded history under.
     *
     * @since 1.7.0
     */
    public const PLUGIN_TRACK = 'plugin:' . AuthKit::ID;

    /**
     * @var string The module-era migration track.
     *
     * @since 1.7.0
     */
    public const MODULE_TRACK = 'module:' . AuthKit::ID;

    /**
     * @var string The module-track name of the install migration. Plugin-era
     * installs recorded the same schema work under the bare class name
     * `Install`; the module track discovers it as this dated wrapper.
     *
     * @since 1.7.0
     */
    private const INSTALL_MIGRATION = 'm260617_000000_Install';

    // Static Methods
    // =========================================================================

    /**
     * Adopts a plugin-era Auth Kit install onto the module track and brings
     * the schema fully up to date. See the class docblock for the exact
     * steps. Idempotent; safe on installs that never had the plugin.
     *
     * Call from a consumer's upgrade migration:
     *
     * ```php
     * public function safeUp(): bool
     * {
     *     \craftpulse\authkit\migrations\Adoption::adoptFromPlugin();
     *
     *     return true;
     * }
     * ```
     *
     * @throws \Throwable if the plugin-era registration cannot be removed, or a
     * pending Auth Kit migration fails to apply
     *
     * @author CraftPulse
     * @since 1.7.0
     */
    public static function adoptFromPlugin(): void
    {
        self::_adoptMigrationHistory();
        self::_removePluginRegistration();

        AuthKit::getInstance()->getMigrator()->up();
    }

    // Private Methods
    // =========================================================================

    /**
     * Copies the plugin era's applied-migration history onto the module track,
     * then deletes the orphaned plugin-track rows.
     *
     * Only migrations the plugin era verifiably applied are marked: the dated
     * deltas are copied name-for-name from the `plugin:auth-kit` history, and
     * the install migration is marked when the tokens table already exists
     * (plugin installs recorded it under the bare name `Install`, so the name
     * itself cannot be copied). Anything not marked here stays pending and is
     * applied by the `up()` call that follows — and every Auth Kit migration
     * is re-runnable, so even an overlap would be harmless.
     *
     * @author CraftPulse
     * @since 1.7.0
     */
    private static function _adoptMigrationHistory(): void
    {
        $db = Craft::$app->getDb();
        $migrator = AuthKit::getInstance()->getMigrator();

        /** @var string[] $pluginHistory */
        $pluginHistory = (new Query())
            ->select(['name'])
            ->from([CraftTable::MIGRATIONS])
            ->where(['track' => self::PLUGIN_TRACK])
            ->column($db);

        if ($pluginHistory === [] && !$db->tableExists(Table::TOKENS)) {
            // Nothing was ever applied here: a genuinely fresh install.
            return;
        }

        $moduleHistory = array_keys($migrator->getMigrationHistory());
        $adopted = [];

        // The install migration: ground truth is the schema itself.
        if ($db->tableExists(Table::TOKENS)) {
            $adopted[] = self::INSTALL_MIGRATION;
        }

        // The dated deltas: ground truth is the plugin-track history.
        foreach ($pluginHistory as $name) {
            if (preg_match('/^m\d{6}_\d{6}_/', $name) === 1) {
                $adopted[] = $name;
            }
        }

        foreach (array_diff($adopted, $moduleHistory) as $name) {
            $migrator->addMigrationHistory($name);
        }

        Db::delete(CraftTable::MIGRATIONS, ['track' => self::PLUGIN_TRACK], db: $db);
    }

    /**
     * Removes the plugin era's registration: the `plugins.auth-kit` project
     * config entry and the `auth-kit` row in the `plugins` table.
     *
     * Both the loaded config and the external (YAML) config are checked,
     * because an entry left behind in YAML is treated as a plugin that still
     * needs installing on the next external apply. The check alone is not
     * enough to act on it, though, which is why the removal goes through
     * `set(null, force: true)` rather than `remove()`. `remove()` is
     * `set($path, null)`, and `set()` compares the new value against the
     * **loaded** config only: for an entry that survives in YAML alone the
     * loaded value is already `null`, so the comparison reads as unchanged,
     * `set()` returns early without marking the YAML for a rewrite, and the
     * flush below has nothing to do. Forcing the set marks the YAML dirty
     * regardless, so the flush regenerates it without the entry.
     *
     * Project config events are muted and read-only is temporarily lifted
     * across the removal and the flush, mirroring what Craft's own
     * [[\craft\services\Plugins::uninstallPlugin()]] does, and both flags are
     * restored afterwards. Muting matters because nothing may react to this as
     * if a real uninstall were happening, and it has to span the flush as well
     * as the removal: the events fire synchronously inside `set()` (see
     * [[\craft\models\ProjectConfigData::commitChanges()]]), so a mute covering
     * only the removal could still let the flush re-fire them. Lifting
     * read-only matters because an install with `allowAdminChanges` off boots
     * `projectConfig` with `readOnly` on (see
     * [[\craft\helpers\App::projectConfigConfig()]]) and `set()` throws
     * `NotSupportedException` on any real change while it is set, which would
     * fail the consumer's upgrade migration outright.
     *
     * The flush is explicit on purpose. `set()` only commits to the loaded
     * working config and defers persistence to `EVENT_AFTER_REQUEST`, which a
     * migration cannot count on reaching (a console process that exits early,
     * or a harness that boots the app without a request lifecycle, would drop
     * the change and leave the plugin registered). Flushing here writes the
     * config data and, when the install writes YAML automatically, the YAML
     * files, so the removal is durable the moment the migration returns. Where
     * Craft has deliberately turned automatic YAML writing off because external
     * changes are pending (see
     * [[\craft\console\controllers\MigrateController::runAction()]]), the flush
     * writes the stored config only and the developer's YAML is left alone; a
     * `project-config/diff` after the upgrade shows what is still to apply.
     *
     * The database row goes last so a failure between the two steps leaves a
     * registration the next adoption call retries from, rather than a `plugins`
     * table with no row and a project config that still names the plugin. Auth
     * Kit's own tables are never touched.
     *
     * @throws \Throwable if the removal or the flush fails
     *
     * @author CraftPulse
     * @since 1.7.0
     */
    private static function _removePluginRegistration(): void
    {
        $projectConfig = Craft::$app->getProjectConfig();
        $configKey = ProjectConfig::PATH_PLUGINS . '.' . AuthKit::ID;

        $isRegistered = $projectConfig->get($configKey) !== null
            || $projectConfig->get($configKey, true) !== null;

        if ($isRegistered) {
            $muteEvents = $projectConfig->muteEvents;
            $readOnly = $projectConfig->readOnly;
            $projectConfig->muteEvents = true;
            $projectConfig->readOnly = false;

            try {
                $projectConfig->set($configKey, null, 'Adopt Auth Kit as a module', force: true);
                $projectConfig->flush();
            } finally {
                $projectConfig->readOnly = $readOnly;
                $projectConfig->muteEvents = $muteEvents;
            }
        }

        Db::delete(CraftTable::PLUGINS, ['handle' => AuthKit::ID]);
    }
}
