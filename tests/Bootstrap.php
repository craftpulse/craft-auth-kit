<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
 *
 * Pest / PHPUnit bootstrap. Run the suite from Auth Kit's OWN root — its own
 * `vendor/bin/pest` (or `ddev composer test`, which resolves to the same
 * binary) — never via the playground's shared
 * `ddev craft pest -- --configuration=vendor/craftpulse/craft-auth-kit/phpunit.xml.dist`.
 * That shared invocation leaves the process's working directory at the
 * playground's Craft root, not here, so craft-pest-core's InstallsCraft
 * plugin never finds this plugin's `phpunit.xml.dist` and its `<env>` DB
 * overrides in `phpunit.xml.dist` (see the comment there) never apply — Craft
 * boots against the playground's live `db` instead of `db_test` and every
 * fixture this suite writes commits permanently.
 *
 * With the correct invocation the working directory is this plugin's own
 * root, so its own autoloader (already mapping both Craft and the plugin's
 * own `src`/`tests`) is authoritative and craft-pest's TestCase boots the
 * application itself against `db_test` — this file only wires autoloading,
 * installs the plugin under test, pins the process timezone, and lets Pest
 * auto-discover `tests/Pest.php`'s `uses()` bindings.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

$craftBase = getcwd();

// Auth Kit vendors its own `craftcms/cms` (see composer.json) precisely so its
// suite can boot a fully isolated Craft install rather than depend on
// whatever plugins happen to be co-installed in a shared app. Checking for
// `vendor/craftcms/cms` (rather than a `craft` executable, which only exists
// at a consuming project's root, never a plugin's own) confirms this really
// is Auth Kit's own root before autoloading from it.
if ($craftBase === false || !is_dir($craftBase . '/vendor/craftcms/cms')) {
    fwrite(STDERR, "Auth Kit test bootstrap could not locate a standalone Craft install at cwd={$craftBase}.\n");
    fwrite(STDERR, "Run tests from Auth Kit's own root, e.g.:\n");
    fwrite(STDERR, "  ddev exec -d /var/www/html/cms/vendor/craftpulse/craft-auth-kit vendor/bin/pest\n");
    fwrite(STDERR, "  ddev exec -d /var/www/html/cms/vendor/craftpulse/craft-auth-kit composer test\n");
    exit(1);
}

$composerLoader = require $craftBase . '/vendor/autoload.php';

// The plugin's autoload-dev mapping never lands in the consuming project's
// vendor dir, so the test namespace is registered here.
if (is_object($composerLoader) && method_exists($composerLoader, 'addPsr4')) {
    $composerLoader->addPsr4('craftpulse\\authkit\\tests\\', __DIR__ . '/');
}

// Pest auto-discovers tests/Pest.php from the test root once getcwd() is this
// plugin's own root (true for the standalone invocation this file requires
// above), so it is NOT required here as well: doing so registers the same
// `uses()->in(__DIR__)` binding twice and Pest refuses the second, identical
// registration with "Test case can not be used ... already uses the test
// case".

// =============================================================================
// Plugin install — Auth Kit itself. craft-pest-core's InstallsCraft plugin
// (which already booted Craft by this point in the Kernel sequence, see the
// class docblock above) installs Craft core and applies any pending project
// config, but never installs the plugin under test. Every test in this suite
// reaches through `AuthKit::$plugin` (its Tokens/Passwords/Audit/Passkeys
// services), which is null until installed, so without this step every test
// fails on a null plugin access rather than on the behavior it actually
// exercises.
// =============================================================================

if (Craft::$app->getIsInstalled(true)) {
    $plugins = Craft::$app->getPlugins();

    if (!$plugins->isPluginInstalled('auth-kit')) {
        $plugins->installPlugin('auth-kit');
    }
}

// =============================================================================
// Timezone — Craft's own example test-suite bootstrap does the same (Craft
// stores every datetime attribute in UTC and expects the process default
// timezone to already be UTC). Must run AFTER Craft is booted above:
// Application::init() reads the system.timeZone project config value and
// calls date_default_timezone_set() itself (ApplicationTrait::_setTimeZone()),
// clobbering anything set earlier in the request. Without this pinned back to
// UTC afterward, a DateTime built with the process's ambient system timezone
// (never guaranteed UTC in every runner) round-trips through a saved element
// attribute — stored via ->format('Y-m-d H:i:s'), reloaded assuming UTC — and
// comes back shifted, which silently breaks any test that persists a
// DateTime and re-reads it in the same run (e.g. a token expiry check).
// =============================================================================

date_default_timezone_set('UTC');
