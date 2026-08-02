# Upgrading from the Plugin Era

Auth Kit 1.6.x and earlier shipped as a Craft plugin, with composer type `craft-plugin`. From 1.7.0 it ships as a library-shipped Yii module, with composer type `library`. An install that carried the plugin has a stale `auth-kit` row in the `plugins` table, a `plugins.auth-kit` project config entry, and its migration history recorded on the `plugin:auth-kit` track. None of that is reachable by the module, and Craft will keep reporting a missing plugin until it is cleaned up.

The whole upgrade is one call, made once, from a consuming plugin.

## What your plugin ships

In the same release that raises your Auth Kit requirement to `^1.7.0`, ship a normal dated migration containing:

```php
public function safeUp(): bool
{
    \craftpulse\authkit\migrations\Adoption::adoptFromPlugin();

    return true;
}
```

Shipping it in that release matters: the stale plugin registration is then cleaned up on the very `craft up` that follows the Composer update, rather than sitting broken until someone notices.

## What `adoptFromPlugin()` does

Three steps, in order:

1. **Migration history.** Auth Kit's already-applied migrations are marked as applied on the module track, so the module's migrator never replays work the plugin era already did. The dated migrations are copied name for name from the `plugin:auth-kit` history; the install migration is recognised from the presence of the tokens table, because plugin installs recorded it under the bare name `Install`. The orphaned plugin-track rows are then deleted.
2. **Plugin registration.** The `auth-kit` row is removed from the `plugins` table and the `plugins.auth-kit` entry is removed from project config, with project config events muted and the config flushed immediately so the removal survives a console process that exits early. Both the loaded config and the external YAML are checked, so the next external apply cannot restore the entry.
3. **Catch-up.** The module migrator's `up()` runs, applying anything genuinely pending.

Auth Kit's own tables are never touched. This is deliberately not `Plugins::uninstallPlugin()`, which would run the install migration's `safeDown()` and drop the token store along with every live token in it.

## Safety

Every step is idempotent and a no-op where its work is already done, which means all of the following are safe:

- **Re-running it.** A second run finds the history adopted, the registration gone, and nothing pending.
- **Several consumers each shipping one.** When Warp and Warden both ship an adoption migration on the same install, whichever runs first does the work and the other finds nothing left to do.
- **An install that never had the plugin.** With no plugin-era history and no tokens table, the call degrades to a plain `up()` and applies the schema fresh. You do not need to detect the plugin era before calling it.

## Consumer code that does not change

The plugin-to-module conversion left the call sites alone. `AuthKit::$plugin` is still the static shorthand, every service accessor keeps its name, the `auth-kit` translation category still resolves, and the `@craftpulse/authkit` alias is still registered. Code written against Auth Kit 1.6.x keeps compiling and keeps working.

Two things do change:

- **`AuthKit::register()` is now required** in your plugin's `init()`. Under the plugin era Craft loaded and booted Auth Kit for you. Nothing does that now. See [Installation & Setup](installation-setup.md).
- **`AuthKit::getInstance()->getMigrator()->up()` is now required** in your install migration, and a dated migration of your own is how future Auth Kit schema changes reach your users.

## Verifying

After the migration has run, Auth Kit should be invisible to Craft's plugin system and fully present as a module:

```php
// All false or null: Auth Kit is not a plugin any more.
Craft::$app->getPlugins()->isPluginInstalled('auth-kit');
Craft::$app->getPlugins()->isPluginEnabled('auth-kit');
Craft::$app->getPlugins()->getPlugin('auth-kit');

// The module, and its services.
Craft::$app->getModule('auth-kit');
```

The `authkit_tokens` table and every row in it should be exactly as it was.
