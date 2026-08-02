<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\variables;

use Craft;
use craft\elements\User;
use craftpulse\authkit\AuthKit;

/**
 * AuthKitVariable is the `craft.authKit` Twig variable — the front-end's handle
 * onto Auth Kit's passwordless features: whether the current user has passkeys,
 * the list of them for a management UI, and the published URL of the reference
 * WebAuthn client.
 *
 * @author Michael Thomas
 * @since 1.0.0
 */
class AuthKitVariable
{
    // Public Methods
    // =========================================================================

    /**
     * Returns whether the current user has any passkeys enrolled.
     *
     * @return bool
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function hasPasskeys(): bool
    {
        $user = $this->_currentUser();

        return $user !== null && AuthKit::$plugin->getPasskeys()->hasPasskeys($user);
    }

    /**
     * Returns the current user's saved passkeys, or an empty array for a guest.
     *
     * @return array<int, array<string, mixed>>
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function passkeys(): array
    {
        $user = $this->_currentUser();

        return $user !== null ? AuthKit::$plugin->getPasskeys()->getPasskeys($user) : [];
    }

    /**
     * Returns the published URL of the reference WebAuthn client script.
     *
     * @return string
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function webauthnJsUrl(): string
    {
        $url = Craft::$app->getAssetManager()->getPublishedUrl(
            '@craftpulse/authkit/web/assets/dist',
            true,
            'authkit-webauthn.js',
        );

        return $url !== false ? $url : '';
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the logged-in user, or null for a guest.
     *
     * @return User|null
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _currentUser(): ?User
    {
        $user = Craft::$app->getUser()->getIdentity();

        return $user instanceof User ? $user : null;
    }
}
