<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\services;

/**
 * ServicesTrait owns Auth Kit's service component registration and typed
 * accessors.
 *
 * Components are declared in [[config()]], which Craft merges into the plugin's
 * Yii config during construction. Each service gets a typed `getX(): X`
 * accessor that narrows Yii's `?object` return for static analysis. The
 * `@property` tags for property-style access live on this trait's docblock —
 * never duplicate them on the main plugin class.
 *
 * @property-read Audit $audit
 * @property-read Passkeys $passkeys
 * @property-read Passwords $passwords
 * @property-read Tokens $tokens
 *
 * @author Michael Thomas
 * @since 1.0.0
 */
trait ServicesTrait
{
    // Public Methods
    // =========================================================================

    /**
     * Returns the component config Craft merges into the plugin's application config.
     *
     * @return array<string, mixed>
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public static function config(): array
    {
        return [
            'components' => [
                'audit' => ['class' => Audit::class],
                'passkeys' => ['class' => Passkeys::class],
                'passwords' => ['class' => Passwords::class],
                'tokens' => ['class' => Tokens::class],
            ],
        ];
    }

    /**
     * Returns the audit service.
     *
     * @return Audit
     *
     * @author Michael Thomas
     * @since 1.2.0
     */
    public function getAudit(): Audit
    {
        $component = $this->get('audit');
        assert($component instanceof Audit);

        return $component;
    }

    /**
     * Returns the passkeys service.
     *
     * @return Passkeys
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function getPasskeys(): Passkeys
    {
        $component = $this->get('passkeys');
        assert($component instanceof Passkeys);

        return $component;
    }

    /**
     * Returns the passwords service.
     *
     * @return Passwords
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function getPasswords(): Passwords
    {
        $component = $this->get('passwords');
        assert($component instanceof Passwords);

        return $component;
    }

    /**
     * Returns the tokens service.
     *
     * @return Tokens
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function getTokens(): Tokens
    {
        $component = $this->get('tokens');
        assert($component instanceof Tokens);

        return $component;
    }
}
