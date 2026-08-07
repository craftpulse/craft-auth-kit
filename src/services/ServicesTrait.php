<?php
/**
 * Auth Kit module for Craft CMS 5.x
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
 * Components are declared in [[config()]], which `AuthKit::getInstance()`
 * passes to the module constructor (Yii applies the `components` key via
 * `setComponents()` before `init()` runs). Each service gets a typed
 * `getX(): X` accessor that narrows Yii's `?object` return for static
 * analysis. The `@property` tags for property-style access live on this
 * trait's docblock — never duplicate them on the main module class.
 *
 * @property-read Audit $audit
 * @property-read Geo $geo
 * @property-read Locations $locations
 * @property-read Passkeys $passkeys
 * @property-read Passwords $passwords
 * @property-read Sessions $sessions
 * @property-read Tokens $tokens
 *
 * @author CraftPulse
 * @since 1.0.0
 */
trait ServicesTrait
{
    // Public Methods
    // =========================================================================

    /**
     * Returns the component config the module is constructed with.
     *
     * @return array<string, mixed>
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    public static function config(): array
    {
        return [
            'components' => [
                'audit' => ['class' => Audit::class],
                'geo' => ['class' => Geo::class],
                'locations' => ['class' => Locations::class],
                'passkeys' => ['class' => Passkeys::class],
                'passwords' => ['class' => Passwords::class],
                'sessions' => ['class' => Sessions::class],
                'tokens' => ['class' => Tokens::class],
            ],
        ];
    }

    /**
     * Returns the audit service.
     *
     * @return Audit
     *
     * @author CraftPulse
     * @since 1.2.0
     */
    public function getAudit(): Audit
    {
        $component = $this->get('audit');
        assert($component instanceof Audit);

        return $component;
    }

    /**
     * Returns the geo service.
     *
     * @return Geo
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    public function getGeo(): Geo
    {
        $component = $this->get('geo');
        assert($component instanceof Geo);

        return $component;
    }

    /**
     * Returns the locations service.
     *
     * @return Locations
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    public function getLocations(): Locations
    {
        $component = $this->get('locations');
        assert($component instanceof Locations);

        return $component;
    }

    /**
     * Returns the passkeys service.
     *
     * @return Passkeys
     *
     * @author CraftPulse
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
     * @author CraftPulse
     * @since 1.0.0
     */
    public function getPasswords(): Passwords
    {
        $component = $this->get('passwords');
        assert($component instanceof Passwords);

        return $component;
    }

    /**
     * Returns the sessions service.
     *
     * @return Sessions
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    public function getSessions(): Sessions
    {
        $component = $this->get('sessions');
        assert($component instanceof Sessions);

        return $component;
    }

    /**
     * Returns the tokens service.
     *
     * @return Tokens
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    public function getTokens(): Tokens
    {
        $component = $this->get('tokens');
        assert($component instanceof Tokens);

        return $component;
    }
}
