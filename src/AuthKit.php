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
     * @since 1.0.0
     */
    public string $schemaVersion = '1.2.0';

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
