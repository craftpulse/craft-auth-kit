<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit;

use Craft;
use craft\base\Plugin;
use craftpulse\authkit\base\PluginTrait;
use craftpulse\authkit\services\ServicesTrait;

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
 * @author Michael Thomas
 * @since 1.0.0
 */
class AuthKit extends Plugin
{
    // Traits
    // =========================================================================

    use PluginTrait;
    use ServicesTrait;

    // Static Properties
    // =========================================================================

    /**
     * @var AuthKit The plugin instance.
     *
     * @since 1.0.0
     */
    public static AuthKit $plugin;

    // Public Properties
    // =========================================================================

    /**
     * @var bool Whether the plugin has its own section in the control panel.
     *
     * @since 1.0.0
     */
    public bool $hasCpSection = false;

    /**
     * @var bool Whether the plugin has a settings page in the control panel.
     *
     * @since 1.0.0
     */
    public bool $hasCpSettings = false;

    /**
     * @var string The plugin's schema version.
     *
     * This is an independent, monotonic schema counter, NOT the plugin's release
     * version, and the two deliberately do not track each other. Craft looks for
     * pending plugin migrations only when this value is ahead of the one recorded
     * in the `plugins` table ([[craft\services\Plugins::isPluginUpdatePending()]]
     * compares them with `version_compare($plugin->schemaVersion, $stored, '>')`),
     * so it must be bumped whenever a migration is added, and must NOT be bumped
     * for a release that adds none. Every migration so far has carried its bump:
     * 1.0.0 at install, 1.1.0 with `m260711_000001_MakeTokenUserIdNullable`
     * (released in 1.2.0), 1.2.0 with `m260716_000001_AddTokenOrigin` (1.4.0),
     * and 1.3.0 with `m260718_000001_AddTokenSubject` (1.6.0). Read the migration
     * classes' `@since` tags as release versions, not as schema versions.
     *
     * @since 1.0.0
     */
    public string $schemaVersion = '1.3.0';

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function init(): void
    {
        parent::init();
        self::$plugin = $this;

        Craft::setAlias('@craftpulse/authkit', __DIR__);

        Craft::$app->onInit(function() {
            $this->_attachEventHandlers();
        });
    }
}
