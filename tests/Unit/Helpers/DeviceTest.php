<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Unit tests for the coarse device labeller: common browser and OS families
 * resolve to a friendly "Browser on OS" string, the more specific family wins
 * when user-agents embed compatibility tokens (Edge/Opera over Chrome, Chrome
 * over Safari), and anything unrecognised or missing falls back to a generic
 * label. This is display-only labelling, not fingerprinting.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craftpulse\authkit\helpers\Device;

it('falls back to a generic label for a missing or empty user-agent', function(?string $userAgent) {
    expect(Device::label($userAgent))->toBe('Unknown device');
})->with([
    'null' => [null],
    'empty' => [''],
    'whitespace' => ['   '],
]);

it('falls back to a generic label for an unrecognisable user-agent', function() {
    expect(Device::label('curl/8.4.0'))->toBe('Unknown device');
});

it('labels common browser and OS combinations', function(string $userAgent, string $expected) {
    expect(Device::label($userAgent))->toBe($expected);
})->with([
    'Chrome on macOS' => [
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Chrome on macOS',
    ],
    'Safari on iOS' => [
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
        'Safari on iOS',
    ],
    'Firefox on Windows' => [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Firefox on Windows',
    ],
    'Edge over Chrome on Windows' => [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
        'Edge on Windows',
    ],
    'Opera over Chrome on Windows' => [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0',
        'Opera on Windows',
    ],
    'Chrome on Android' => [
        'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        'Chrome on Android',
    ],
    'Chrome on Linux' => [
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Chrome on Linux',
    ],
]);

it('labels a known browser with no recognisable OS by browser alone', function() {
    expect(Device::label('Chrome/120.0.0.0'))->toBe('Chrome');
});

it('labels a known OS with no recognisable browser by OS alone', function() {
    expect(Device::label('Mozilla/5.0 (Windows NT 10.0)'))->toBe('Windows');
});

it('classifies the coarse device type for a user-agent', function(string $userAgent, string $expected) {
    expect(Device::type($userAgent))->toBe($expected);
})->with([
    'desktop macOS' => [
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        Device::TYPE_DESKTOP,
    ],
    'desktop Windows' => [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        Device::TYPE_DESKTOP,
    ],
    'mobile iPhone' => [
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
        Device::TYPE_MOBILE,
    ],
    'mobile Android phone' => [
        'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        Device::TYPE_MOBILE,
    ],
    'tablet iPad' => [
        'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/604.1',
        Device::TYPE_TABLET,
    ],
    'tablet Android' => [
        'Mozilla/5.0 (Linux; Android 14; SM-X710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        Device::TYPE_TABLET,
    ],
]);

it('classifies a missing or unrecognisable user-agent as unknown', function(?string $userAgent) {
    expect(Device::type($userAgent))->toBe(Device::TYPE_UNKNOWN);
})->with([
    'null' => [null],
    'empty' => [''],
    'unrecognisable' => ['curl/8.4.0'],
]);
