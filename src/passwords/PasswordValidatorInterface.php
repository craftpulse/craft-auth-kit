<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\passwords;

use craft\elements\User;

/**
 * PasswordValidatorInterface is the cooperation seam for password policy and
 * breach checks. Consumers (Warden, Warp) call the Auth Kit `passwords`
 * service on any set-password or registration flow; a provider plugin (e.g.
 * Password Policy) ships a thin adapter implementing this interface,
 * delegating to its own strength/breach logic.
 *
 * The contract is deliberately tiny and neutral — no plugin-detection, no
 * coupling. If no validator is registered the service is a graceful no-op.
 * Treat any change to this interface as a major version bump (see PLAN §8).
 *
 * @author Michael Thomas
 * @since 1.0.0
 */
interface PasswordValidatorInterface
{
    // Public Methods
    // =========================================================================

    /**
     * Validates a candidate password, optionally in the context of the user it
     * is being set for.
     *
     * @param string $password the candidate password
     * @param User|null $user the user the password is for, when known
     * @return PasswordValidationResult the validator's verdict
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function validate(string $password, ?User $user): PasswordValidationResult;
}
