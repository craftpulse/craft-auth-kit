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

use craft\elements\User;
use craftpulse\authkit\events\RegisterPasswordValidatorsEvent;
use craftpulse\authkit\passwords\PasswordValidationResult;
use craftpulse\authkit\passwords\PasswordValidatorInterface;
use yii\base\Component;

/**
 * Passwords holds a registry of [[PasswordValidatorInterface]] implementations
 * and runs every registered validator against a candidate password,
 * aggregating their verdicts.
 *
 * This is the cooperation seam described in PLAN §4: a consumer (Warden, Warp)
 * calls [[validate()]] on any set-password or registration flow, and any
 * provider plugin (e.g. Password Policy) contributes a validator via the
 * [[EVENT_REGISTER_PASSWORD_VALIDATORS]] event or [[setValidators()]]. With no
 * validators registered the service is a graceful no-op — every password is
 * valid.
 *
 * An instance of the service is available via `AuthKit::$plugin->getPasswords()`.
 *
 * @author CraftPulse
 * @since 1.0.0
 */
class Passwords extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * @event RegisterPasswordValidatorsEvent The event that is triggered when
     * the validator registry is first assembled, letting provider plugins
     * contribute their own [[PasswordValidatorInterface]] implementations.
     * @since 1.0.0
     */
    public const EVENT_REGISTER_PASSWORD_VALIDATORS = 'registerPasswordValidators';

    // Private Properties
    // =========================================================================

    /**
     * @var PasswordValidatorInterface[]|null The resolved validators, lazily
     * assembled from the registration event on first use.
     *
     * @since 1.0.0
     */
    private ?array $_validators = null;

    // Public Methods
    // =========================================================================

    /**
     * Returns the registered password validators, assembling them from the
     * registration event on first access.
     *
     * @return PasswordValidatorInterface[]
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    public function getValidators(): array
    {
        if ($this->_validators === null) {
            $event = new RegisterPasswordValidatorsEvent();
            $this->trigger(self::EVENT_REGISTER_PASSWORD_VALIDATORS, $event);
            $this->_validators = $event->validators;
        }

        return $this->_validators;
    }

    /**
     * Replaces the registered validators. Primarily for tests and explicit
     * wiring; runtime registration goes through the event.
     *
     * @param PasswordValidatorInterface[] $validators the validators to register
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    public function setValidators(array $validators): void
    {
        $this->_validators = array_values($validators);
    }

    /**
     * Runs every registered validator against a candidate password and returns
     * the aggregate verdict — invalid if any validator rejected, with all of
     * their error messages collected. With no validators registered the result
     * is valid.
     *
     * @param string $password the candidate password
     * @param User|null $user the user the password is for, when known
     * @return PasswordValidationResult the aggregate verdict
     *
     * @author CraftPulse
     * @since 1.0.0
     */
    public function validate(string $password, ?User $user = null): PasswordValidationResult
    {
        $errors = [];

        foreach ($this->getValidators() as $validator) {
            $result = $validator->validate($password, $user);

            if (!$result->isValid) {
                $errors = array_merge($errors, $result->errors);
            }
        }

        return $errors === [] ? PasswordValidationResult::valid() : PasswordValidationResult::invalid($errors);
    }
}
