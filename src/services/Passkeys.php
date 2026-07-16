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

use Craft;
use craft\elements\User;
use craft\services\Auth;
use yii\base\Component;
use yii\web\ForbiddenHttpException;

/**
 * Passkeys exposes core's WebAuthn machinery (`craft\services\Auth`) to
 * front-end users, who can never reach the CP-only controller core ships it
 * behind, and enforces the recent-authentication gate on the
 * credential-changing operations: [[verifyCreation()]] and [[deletePasskey()]]
 * throw a [[ForbiddenHttpException]] when the session has not authenticated
 * within [[recentAuthDuration]] seconds.
 *
 * Auth Kit does not re-implement any WebAuthn crypto: creation options,
 * attestation verification, assertion, and credential storage all run through
 * core's already-conformance-tested `Auth` service. Passkey *login* is left to
 * core's own anonymous endpoints; this service only covers the operations a
 * logged-in user performs on their own credentials.
 *
 * Recent-auth gate: passwordless users have no password to satisfy core's
 * `requireElevatedSession()`, so sensitive operations instead require that the
 * user authenticated — by any means — within [[recentAuthDuration]] seconds.
 * The timestamp is refreshed on every login via the handler in `PluginTrait`.
 *
 * The gate authenticates the *session*, not the target: authorization is
 * scoped entirely by the `$user` argument the caller passes. Callers must
 * always pass the authenticated user's own element — never a user resolved
 * from request input.
 *
 * An instance of the service is available via `AuthKit::$plugin->getPasskeys()`.
 *
 * @author Michael Thomas
 * @since 1.0.0
 */
class Passkeys extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * @var int The default recent-auth window, in seconds (5 minutes) —
     * mirrors core's `elevatedSessionDuration` default.
     *
     * @since 1.0.0
     */
    public const DEFAULT_RECENT_AUTH_DURATION = 300;

    /**
     * @var string The session key holding the last authentication timestamp.
     *
     * @since 1.0.0
     */
    public const SESSION_RECENT_AUTH_KEY = 'authkit:recentAuthAt';

    // Public Properties
    // =========================================================================

    /**
     * @var int How recently the user must have authenticated, in seconds, to
     * pass the recent-auth gate.
     *
     * @since 1.0.0
     */
    public int $recentAuthDuration = self::DEFAULT_RECENT_AUTH_DURATION;

    // Public Methods
    // =========================================================================

    /**
     * Deletes one of a user's passkeys by its UID.
     *
     * Core scopes the delete to `userId + uid`, so `$user` is the whole
     * authorization boundary — always pass the authenticated user.
     *
     * Returns whether a credential was actually removed. Core's delete is a
     * silent no-op for an unknown UID, so the presence check happens here —
     * consumers use the return value to keep audit trails factual (never
     * record a deletion that did not happen). The check-then-delete is not
     * atomic: two concurrent deletes of the same UID can both observe it as
     * held and double-count one removal in an audit trail — an accepted
     * residual (core's delete itself is idempotent; no authorization impact).
     *
     * @param User $user the credential's owner
     * @param string $uid the passkey UID to delete
     * @return bool whether the user held a passkey with that UID and it was removed
     * @throws ForbiddenHttpException if the session has not authenticated within [[recentAuthDuration]] seconds
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function deletePasskey(User $user, string $uid): bool
    {
        $this->_requireRecentAuth();

        $auth = $this->_auth();
        $held = in_array($uid, array_column($auth->getPasskeys($user), 'uid'), true);

        if (!$held) {
            return false;
        }

        $auth->deletePasskey($user, $uid);

        return true;
    }

    /**
     * Returns the serialized passkey creation options for a user, ready to be
     * handed to `navigator.credentials.create()` on the front end. Core stashes
     * the matching options in the session for verification.
     *
     * @param User $user the user enrolling a passkey
     * @return string the JSON-serialized creation options
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function getCreationOptions(User $user): string
    {
        $auth = $this->_auth();
        $options = $auth->getPasskeyCreationOptions($user);

        return $auth->webauthnServer()->getSerializer()->serialize($options, 'json');
    }

    /**
     * Returns info about a user's saved passkeys.
     *
     * @param User $user the credential owner
     * @return array<int, array<string, mixed>>
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function getPasskeys(User $user): array
    {
        return $this->_auth()->getPasskeys($user);
    }

    /**
     * Returns whether the current session authenticated recently enough to
     * pass the recent-auth gate.
     *
     * @param int|null $within the window in seconds, or null for [[recentAuthDuration]]
     * @return bool
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function hasRecentAuth(?int $within = null): bool
    {
        $stampedAt = $this->_session()->get(self::SESSION_RECENT_AUTH_KEY);

        if (!is_int($stampedAt) && !is_numeric($stampedAt)) {
            return false;
        }

        $within ??= $this->recentAuthDuration;

        return (time() - (int)$stampedAt) <= $within;
    }

    /**
     * Returns whether a user has any saved passkeys.
     *
     * @param User $user the user to check
     * @return bool
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function hasPasskeys(User $user): bool
    {
        return $this->_auth()->hasPasskeys($user);
    }

    /**
     * Records the current session as having just authenticated. Called from the
     * login handler so every login path refreshes the recent-auth window
     * consistently.
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function stampRecentAuth(): void
    {
        $this->_session()->set(self::SESSION_RECENT_AUTH_KEY, time());
    }

    /**
     * Verifies a passkey creation response and stores the credential.
     *
     * @param string $credentials the JSON attestation response from the authenticator
     * @param string|null $credentialName an optional label for the passkey
     * @return bool whether the credential was verified and stored
     * @throws ForbiddenHttpException if the session has not authenticated within [[recentAuthDuration]] seconds
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function verifyCreation(string $credentials, ?string $credentialName = null): bool
    {
        $this->_requireRecentAuth();

        return $this->_auth()->verifyPasskeyCreationResponse($credentials, $credentialName);
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns core's auth service.
     *
     * @return Auth
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _auth(): Auth
    {
        $auth = Craft::$app->getAuth();
        assert($auth instanceof Auth);

        return $auth;
    }

    /**
     * Enforces the recent-auth gate for a credential-changing operation, so a
     * caller that skips the check cannot ship an ungated enrollment or
     * deletion path.
     *
     * @throws ForbiddenHttpException if the session has not authenticated within [[recentAuthDuration]] seconds
     *
     * @author Michael Thomas
     * @since 1.0.1
     */
    private function _requireRecentAuth(): void
    {
        if (!$this->hasRecentAuth()) {
            throw new ForbiddenHttpException('Recent authentication is required to manage passkeys.');
        }
    }

    /**
     * Returns Craft's session component. The recent-auth state is browser-bound
     * and lives in the user's session.
     *
     * @return \craft\web\Session
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    private function _session(): \craft\web\Session
    {
        /** @var \craft\web\Application $app */
        $app = Craft::$app;

        return $app->getSession();
    }
}
