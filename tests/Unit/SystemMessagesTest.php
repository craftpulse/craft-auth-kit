<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Copy contract for the four emails Auth Kit registers. Each one carries a
 * credential with a finite lifetime, and each body must state that lifetime
 * exactly through the `expiresIn` variable the tokens service passes — a hedge
 * like "expires shortly" leaves the recipient guessing whether they have a
 * minute or a day.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craftpulse\authkit\services\Tokens;

/**
 * Returns the registered body copy for a message key.
 */
function messageBody(string $key): string
{
    $message = Craft::$app->getSystemMessages()->getMessage($key);

    return (string)$message->body;
}

it('states the exact expiry in every email it registers', function(string $key) {
    $body = messageBody($key);

    expect($body)->toContain('{{ expiresIn }}')
        ->and($body)->not->toContain('shortly');
})->with([
    Tokens::MESSAGE_KEY_MAGIC_LINK,
    Tokens::MESSAGE_KEY_OTP,
    Tokens::MESSAGE_KEY_GUEST_OTP,
    Tokens::MESSAGE_KEY_REGISTER,
]);
