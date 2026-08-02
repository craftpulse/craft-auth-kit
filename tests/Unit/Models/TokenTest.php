<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Tests for the Token model: validation rules and the usability helpers that
 * the consume path relies on (expired / consumed / out-of-attempts / usable).
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craft\helpers\DateTimeHelper;
use craftpulse\authkit\models\Token;

it('treats a future, unconsumed token as usable', function() {
    $token = new Token([
        'userId' => 1,
        'type' => Token::TYPE_MAGIC_LINK,
        'tokenHash' => str_repeat('a', 64),
        'expiryDate' => (clone DateTimeHelper::now())->modify('+15 minutes'),
    ]);

    expect($token->isExpired())->toBeFalse()
        ->and($token->isConsumed())->toBeFalse()
        ->and($token->isOutOfAttempts())->toBeFalse()
        ->and($token->isUsable())->toBeTrue();
});

it('treats a past-expiry token as expired and unusable', function() {
    $token = new Token([
        'userId' => 1,
        'type' => Token::TYPE_MAGIC_LINK,
        'tokenHash' => str_repeat('a', 64),
        'expiryDate' => (clone DateTimeHelper::now())->modify('-1 second'),
    ]);

    expect($token->isExpired())->toBeTrue()
        ->and($token->isUsable())->toBeFalse();
});

it('fails closed when a token has no expiry', function() {
    $token = new Token([
        'userId' => 1,
        'type' => Token::TYPE_MAGIC_LINK,
        'tokenHash' => str_repeat('a', 64),
    ]);

    expect($token->isExpired())->toBeTrue()
        ->and($token->isUsable())->toBeFalse();
});

it('treats a consumed token as unusable even before expiry', function() {
    $token = new Token([
        'userId' => 1,
        'type' => Token::TYPE_MAGIC_LINK,
        'tokenHash' => str_repeat('a', 64),
        'expiryDate' => (clone DateTimeHelper::now())->modify('+15 minutes'),
        'dateConsumed' => DateTimeHelper::now(),
    ]);

    expect($token->isConsumed())->toBeTrue()
        ->and($token->isExpired())->toBeFalse()
        ->and($token->isUsable())->toBeFalse();
});

it('treats an OTP at its attempt cap as out of attempts and unusable', function() {
    $token = new Token([
        'userId' => 1,
        'type' => Token::TYPE_OTP,
        'tokenHash' => str_repeat('a', 64),
        'expiryDate' => (clone DateTimeHelper::now())->modify('+15 minutes'),
        'maxAttempts' => 5,
        'attempts' => 5,
    ]);

    expect($token->isOutOfAttempts())->toBeTrue()
        ->and($token->isUsable())->toBeFalse();
});

it('never treats a null-cap token as out of attempts', function() {
    $token = new Token([
        'userId' => 1,
        'type' => Token::TYPE_MAGIC_LINK,
        'tokenHash' => str_repeat('a', 64),
        'expiryDate' => (clone DateTimeHelper::now())->modify('+15 minutes'),
        'maxAttempts' => null,
        'attempts' => 999,
    ]);

    expect($token->isOutOfAttempts())->toBeFalse()
        ->and($token->isUsable())->toBeTrue();
});

it('requires a userId, type, token hash, and expiry', function() {
    $token = new Token();

    expect($token->validate())->toBeFalse()
        ->and($token->getErrors())->toHaveKeys(['userId', 'type', 'tokenHash', 'expiryDate']);
});

it('rejects an unknown token type', function() {
    $token = new Token([
        'userId' => 1,
        'type' => 'sms',
        'tokenHash' => str_repeat('a', 64),
        'expiryDate' => (clone DateTimeHelper::now())->modify('+15 minutes'),
    ]);

    expect($token->validate())->toBeFalse()
        ->and($token->getErrors())->toHaveKey('type');
});

it('rejects a token hash that is not 64 characters', function() {
    $token = new Token([
        'userId' => 1,
        'type' => Token::TYPE_MAGIC_LINK,
        'tokenHash' => 'too-short',
        'expiryDate' => (clone DateTimeHelper::now())->modify('+15 minutes'),
    ]);

    expect($token->validate())->toBeFalse()
        ->and($token->getErrors())->toHaveKey('tokenHash');
});

it('accepts a registration token with no userId', function() {
    // A registration token is issued before its user exists — the email lives
    // in the payload — so a null userId must validate for this type alone.
    $token = new Token([
        'userId' => null,
        'type' => Token::TYPE_REGISTER,
        'tokenHash' => str_repeat('a', 64),
        'expiryDate' => (clone DateTimeHelper::now())->modify('+15 minutes'),
        'payload' => ['email' => 'newcomer@authkit-test.example'],
    ]);

    expect($token->validate())->toBeTrue()
        ->and($token->getErrors())->toBeEmpty();
});

it('accepts a guest OTP token with no userId but requires its subject', function() {
    // A guest OTP proves control of an arbitrary mailbox — no user exists — and
    // is looked up by its subject, so a null userId validates but a null subject
    // does not.
    $token = new Token([
        'userId' => null,
        'type' => Token::TYPE_GUEST_OTP,
        'subject' => str_repeat('b', 64),
        'tokenHash' => str_repeat('a', 64),
        'expiryDate' => (clone DateTimeHelper::now())->modify('+15 minutes'),
    ]);

    expect($token->validate())->toBeTrue()
        ->and($token->getErrors())->toBeEmpty();

    $token->subject = null;

    expect($token->validate())->toBeFalse()
        ->and($token->getErrors())->toHaveKey('subject');
});

it('accepts guest-otp as a known token type', function() {
    $token = new Token([
        'userId' => null,
        'type' => Token::TYPE_GUEST_OTP,
        'subject' => str_repeat('b', 64),
        'tokenHash' => str_repeat('a', 64),
        'expiryDate' => (clone DateTimeHelper::now())->modify('+15 minutes'),
    ]);

    expect($token->validate())->toBeTrue()
        ->and($token->getErrors())->not->toHaveKey('type');
});

it('still requires a userId for a magic-link token', function() {
    $token = new Token([
        'userId' => null,
        'type' => Token::TYPE_MAGIC_LINK,
        'tokenHash' => str_repeat('a', 64),
        'expiryDate' => (clone DateTimeHelper::now())->modify('+15 minutes'),
    ]);

    expect($token->validate())->toBeFalse()
        ->and($token->getErrors())->toHaveKey('userId');
});

it('still requires a userId for an OTP token', function() {
    $token = new Token([
        'userId' => null,
        'type' => Token::TYPE_OTP,
        'tokenHash' => str_repeat('a', 64),
        'expiryDate' => (clone DateTimeHelper::now())->modify('+15 minutes'),
    ]);

    expect($token->validate())->toBeFalse()
        ->and($token->getErrors())->toHaveKey('userId');
});

it('accepts register as a known token type', function() {
    $token = new Token([
        'type' => Token::TYPE_REGISTER,
        'tokenHash' => str_repeat('a', 64),
        'expiryDate' => (clone DateTimeHelper::now())->modify('+15 minutes'),
    ]);

    expect($token->validate())->toBeTrue()
        ->and($token->getErrors())->not->toHaveKey('type');
});
