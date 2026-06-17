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

use craft\base\Model;

/**
 * PasswordValidationResult is the neutral verdict a [[PasswordValidatorInterface]]
 * returns: whether a candidate password is acceptable, and if not, the
 * human-readable reasons why.
 *
 * The aggregate result the [[\craftpulse\authkit\services\Passwords]] service
 * returns merges every registered validator's verdict — invalid if any
 * validator rejected, with all of their errors collected.
 *
 * @author Michael Thomas
 * @since 1.0.0
 */
class PasswordValidationResult extends Model
{
    // Public Properties
    // =========================================================================

    /**
     * @var string[] The reasons the password was rejected, empty when valid.
     *
     * @since 1.0.0
     */
    public array $errors = [];

    /**
     * @var bool Whether the password is acceptable.
     *
     * @since 1.0.0
     */
    public bool $isValid = true;

    // Public Methods
    // =========================================================================

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
        return new self(['isValid' => false, 'errors' => array_values($errors)]);
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
        return new self(['isValid' => true, 'errors' => []]);
    }
}
