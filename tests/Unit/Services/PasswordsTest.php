<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
 *
 * Tests for the passwords service: the validator registry no-op default, and
 * the aggregation of a registered failing validator's verdict and errors.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craft\elements\User;
use craftpulse\authkit\passwords\PasswordValidationResult;
use craftpulse\authkit\passwords\PasswordValidatorInterface;
use craftpulse\authkit\services\Passwords;

it('treats every password as valid when no validators are registered', function() {
    $service = new Passwords();
    $service->setValidators([]);

    $result = $service->validate('anything');

    expect($result->isValid)->toBeTrue()
        ->and($result->errors)->toBe([]);
});

it('rejects a password when a registered validator fails, collecting its errors', function() {
    $failing = new class() implements PasswordValidatorInterface {
        public function validate(string $password, ?User $user): PasswordValidationResult
        {
            return PasswordValidationResult::invalid(['Too weak.', 'Found in a breach.']);
        }
    };

    $service = new Passwords();
    $service->setValidators([$failing]);

    $result = $service->validate('hunter2');

    expect($result->isValid)->toBeFalse()
        ->and($result->errors)->toBe(['Too weak.', 'Found in a breach.']);
});

it('aggregates errors across multiple validators and stays valid when all pass', function() {
    $passing = new class() implements PasswordValidatorInterface {
        public function validate(string $password, ?User $user): PasswordValidationResult
        {
            return PasswordValidationResult::valid();
        }
    };
    $failing = new class() implements PasswordValidatorInterface {
        public function validate(string $password, ?User $user): PasswordValidationResult
        {
            return PasswordValidationResult::invalid(['Nope.']);
        }
    };

    $allPass = new Passwords();
    $allPass->setValidators([$passing, $passing]);
    expect($allPass->validate('ok')->isValid)->toBeTrue();

    $oneFails = new Passwords();
    $oneFails->setValidators([$passing, $failing]);
    $result = $oneFails->validate('ok');
    expect($result->isValid)->toBeFalse()
        ->and($result->errors)->toBe(['Nope.']);
});

it('assembles validators from the registration event on first use', function() {
    $service = new Passwords();

    $handler = function(\craftpulse\authkit\events\RegisterPasswordValidatorsEvent $event): void {
        $event->validators[] = new class() implements PasswordValidatorInterface {
            public function validate(string $password, ?User $user): PasswordValidationResult
            {
                return PasswordValidationResult::invalid(['From the event.']);
            }
        };
    };
    $service->on(Passwords::EVENT_REGISTER_PASSWORD_VALIDATORS, $handler);

    $result = $service->validate('whatever');

    expect($result->isValid)->toBeFalse()
        ->and($result->errors)->toBe(['From the event.']);
});
