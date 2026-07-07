<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
 *
 * A security component spy that counts bcrypt verifications, so tests can
 * assert code-path timing equivalence deterministically: every enumeration-
 * sensitive branch must perform exactly as many fixed-cost verifications as
 * its sibling branches, instead of relying on flaky wall-clock measurement.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\tests\Support;

use craft\services\Security;

final class CountingSecurity extends Security
{
    /**
     * @var int The number of validatePassword() calls observed.
     */
    public int $validatePasswordCalls = 0;

    /**
     * @inheritdoc
     */
    public function validatePassword($password, $hash): bool
    {
        $this->validatePasswordCalls++;

        return parent::validatePassword($password, $hash);
    }
}
