<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit;

use Craft;
use craft\db\MigrationManager;
use craft\i18n\PhpMessageSource;
use craftpulse\authkit\base\PluginTrait;
use craftpulse\authkit\services\ServicesTrait;
use yii\base\Module;

/**
 * Auth Kit is the free, foundational authentication base for the CraftPulse
 * security ecosystem. It owns the unified passwordless token store (magic
 * links + email OTP), thin passkey wrappers over core's WebAuthn machinery, a
 * recent-auth gate, and the password-validator cooperation contract.
 *
 * Auth Kit is primitives + contracts: it ships no routes, controllers, or UX —
 * consuming plugins (Warden, Warp, Password Policy) own those and call into
 * Auth Kit's services.
 *
 * As of 1.7.0 Auth Kit is a library-shipped Yii module, not a Craft plugin
 * (mirroring the `verbb/auth` model). It never appears in Craft's
 * installed-plugins list and cannot be enabled or disabled on its own.
 * Consuming plugins wire it up with exactly three calls:
 *
 * - `AuthKit::register()` from the consumer plugin's `init()` — idempotent,
 *   so Warp and Warden can both call it on the same install.
 * - `AuthKit::getInstance()->getMigrator()->up()` from the consumer's
 *   `Install` migration — applies Auth Kit's own migrations on the
 *   `module:auth-kit` track.
 * - `Adoption::adoptFromPlugin()` from a one-time consumer upgrade migration —
 *   converts a plugin-era install (see [[migrations\Adoption]]).
 *
 * @author Michael Thomas
 * @since 1.0.0
 */
class AuthKit extends Module
{
    // Traits
    // =========================================================================

    use PluginTrait;
    use ServicesTrait;

    // Const Properties
    // =========================================================================

    /**
     * @var string The application module ID Auth Kit registers itself under,
     * and the suffix of its migration track (`module:auth-kit`). Also doubles
     * as the translation category, preserving every plugin-era
     * `Craft::t('auth-kit', ...)` call site.
     *
     * @since 1.7.0
     */
    public const ID = 'auth-kit';

    // Static Properties
    // =========================================================================

    /**
     * @var AuthKit The module instance.
     *
     * Kept under the plugin-era `$plugin` name so every existing
     * `AuthKit::$plugin->...` call site in consumers keeps working unchanged
     * across the plugin-to-module conversion.
     *
     * @since 1.0.0
     */
    public static AuthKit $plugin;

    // Static Methods
    // =========================================================================

    /**
     * Registers Auth Kit as an application module, idempotently.
     *
     * This is the consumer entry point: every consuming plugin calls it from
     * its own `init()`. The first call creates the module, sets it on the
     * application under [[ID]], and attaches Auth Kit's event handlers (via
     * `Craft::$app->onInit()`, which fires immediately when the app is already
     * initialized). Every subsequent call — Warp and Warden will both make one
     * on the same install — returns the existing instance and does nothing
     * else.
     *
     * @return AuthKit
     *
     * @author Michael Thomas
     * @since 1.7.0
     */
    public static function register(): AuthKit
    {
        return static::getInstance();
    }

    /**
     * Returns the Auth Kit module instance, registering it on the application
     * first if no consumer has done so yet.
     *
     * Mirrors the `verbb/auth` idiom: lazy, idempotent, and safe to call from
     * any context (web, console, queue, migrations). Prefer [[register()]] in
     * consumer plugin `init()` methods for intent; use this accessor
     * everywhere else.
     *
     * @return AuthKit
     *
     * @author Michael Thomas
     * @since 1.7.0
     */
    public static function getInstance(): AuthKit
    {
        $module = Craft::$app->getModule(self::ID);

        if ($module instanceof self) {
            return $module;
        }

        $module = new AuthKit(self::ID, Craft::$app);
        Craft::$app->setModule(self::ID, $module);

        return $module;
    }

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function init(): void
    {
        parent::init();

        // Only the canonically-registered module claims the singleton. A
        // module constructed under any other ID (a test fixture, or a second
        // instance an install declares in `config/app.php` by mistake) is a
        // working object but must never displace the instance the whole
        // ecosystem reaches through, or every consumer's `AuthKit::$plugin`
        // would silently start pointing at it.
        if ($this->id === self::ID) {
            self::setInstance($this);
            self::$plugin = $this;
        }

        Craft::setAlias('@craftpulse/authkit', __DIR__);

        $this->_registerComponents();
        $this->_registerTranslations();
        $this->_registerMigrator();

        Craft::$app->onInit(function() {
            $this->_attachEventHandlers();
        });
    }

    /**
     * Returns Auth Kit's migration manager, which runs the module's own
     * migrations on the `module:auth-kit` track.
     *
     * Consumers call `AuthKit::getInstance()->getMigrator()->up()` from their
     * `Install` migration so a fresh install of any consumer creates (or
     * fast-forwards) Auth Kit's schema. Multiple consumers calling it is safe:
     * applied migrations are recorded on the module track and never re-run.
     *
     * @return MigrationManager
     *
     * @author Michael Thomas
     * @since 1.7.0
     */
    public function getMigrator(): MigrationManager
    {
        $component = $this->get('migrator');
        assert($component instanceof MigrationManager);

        return $component;
    }

    // Private Methods
    // =========================================================================

    /**
     * Fills in Auth Kit's service components, leaving any already-defined
     * definition alone.
     *
     * Auth Kit's services carry no settings model; they are tuned by setting
     * properties on the components themselves, which an install does through
     * `config/app.php`:
     *
     * ```php
     * 'modules' => [
     *     'auth-kit' => [
     *         'class' => \craftpulse\authkit\AuthKit::class,
     *         'components' => [
     *             'tokens' => ['tokenTtl' => 600],
     *         ],
     *     ],
     * ],
     * ```
     *
     * Yii instantiates a module declared that way from that config alone, and
     * [[\yii\di\ServiceLocator::setComponents()]] overwrites rather than
     * merges — so registering the defaults wholesale would either clobber the
     * install's override or, applied the other way round, leave the three
     * services the install did not mention undefined. Filling in only what is
     * missing makes a partial override partial, which is the only behavior
     * that is safe to document.
     *
     * The "is it already defined" test reads this module's OWN definitions
     * rather than calling `has()`. [[\yii\base\Module::has()]] and
     * [[\yii\base\Module::get()]] both fall back to the parent module, and
     * this module's parent is the Craft application, which already carries a
     * `tokens` component of its own ([[\craft\services\Tokens]]). A `has()`
     * test therefore reports Auth Kit's `tokens` as already defined, skips it,
     * and leaves `getTokens()` resolving Craft's token service instead of Auth
     * Kit's — a silent substitution with no error anywhere.
     *
     * @author Michael Thomas
     * @since 1.7.0
     */
    private function _registerComponents(): void
    {
        /** @var array<string, mixed> $components */
        $components = self::config()['components'] ?? [];
        $defined = $this->getComponents();

        foreach ($components as $id => $definition) {
            if (!isset($defined[$id])) {
                $this->set($id, $definition);
            }
        }
    }

    /**
     * Registers the `auth-kit` translation category.
     *
     * Craft only auto-registers translation categories for installed plugins,
     * and `Craft::t()` throws for a category no message source claims — so the
     * module must claim its plugin-era category itself to keep every existing
     * `Craft::t('auth-kit', ...)` call site working.
     *
     * @author Michael Thomas
     * @since 1.7.0
     */
    private function _registerTranslations(): void
    {
        $i18n = Craft::$app->getI18n();

        if (!isset($i18n->translations[self::ID]) && !isset($i18n->translations[self::ID . '*'])) {
            $i18n->translations[self::ID] = [
                'class' => PhpMessageSource::class,
                'sourceLanguage' => 'en',
                'basePath' => __DIR__ . DIRECTORY_SEPARATOR . 'translations',
                'allowOverrides' => true,
            ];
        }
    }

    /**
     * Sets up the module's own migration manager on the `module:auth-kit`
     * track (mirroring `verbb/auth`'s `module:verbb-auth`).
     *
     * A module has no Craft-managed plugin migrator, so Auth Kit owns its own:
     * same [[MigrationManager]] Craft uses for plugins, pointed at this
     * package's `migrations/` directory, with history recorded under the
     * module track in the `migrations` table.
     *
     * @author Michael Thomas
     * @since 1.7.0
     */
    private function _registerMigrator(): void
    {
        $this->set('migrator', [
            'class' => MigrationManager::class,
            'track' => 'module:' . self::ID,
            'migrationNamespace' => 'craftpulse\\authkit\\migrations',
            'migrationPath' => __DIR__ . DIRECTORY_SEPARATOR . 'migrations',
        ]);
    }
}
