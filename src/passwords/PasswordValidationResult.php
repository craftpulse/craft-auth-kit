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

/**
 * PasswordValidationResult is the neutral verdict a [[PasswordValidatorInterface]]
 * returns: whether a candidate password is acceptable, and if not, the
 * human-readable reasons why.
 *
 * This is deliberately a plain final value class rather than a `craft\base\Model`
 * subclass: on a Model, `$errors` would shadow Yii's inherited `getErrors()`
 * validation API — two same-named APIs with different answers. The frozen
 * 1.0.0 shape is exactly two readonly properties ([[isValid]] and [[errors]])
 * plus the two factories; treat any change as a major version bump, alongside
 * [[PasswordValidatorInterface]].
 *
 * The aggregate result the [[\craftpulse\authkit\services\Passwords]] service
 * returns merges every registered validator's verdict — invalid if any
 * validator rejected, with all of their errors collected.
 *
 * @author Michael Thomas
 * @since 1.0.0
 */
final class PasswordValidationResult
{
    // Public Properties
    // =========================================================================

    /**
     * @var string[] The reasons the password was rejected, empty when valid.
     *
     * @since 1.0.0
     */
    public readonly array $errors;

    /**
     * @var bool Whether the password is acceptable.
     *
     * @since 1.0.0
     */
    public readonly bool $isValid;

    // Public Methods
    // =========================================================================

    /**
     * Constructor.
     *
     * @param bool $isValid whether the password is acceptable
     * @param string[] $errors the rejection reasons, empty when valid
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public function __construct(bool $isValid, array $errors = [])
    {
        $this->isValid = $isValid;
        $this->errors = array_values($errors);
    }

    /**
     * Returns a failing result carrying the given error messages.
     *
     * @param string[] $errors the rejection reasons
     * @return self
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public static function invalid(array $errors): self
    {
        return new self(false, $errors);
    }

    /**
     * Returns a passing result with no errors.
     *
     * @return self
     *
     * @author Michael Thomas
     * @since 1.0.0
     */
    public static function valid(): self
    {
        return new self(true);
    }
}
