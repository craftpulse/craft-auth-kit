<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Unit tests for the IP anonymizer: an IPv4 address loses its final octet, an
 * IPv6 address keeps only its /48 routing prefix, missing input stays null,
 * and anything unparseable fails closed to null rather than being stored raw.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craftpulse\authkit\helpers\Ip;

it('zeroes the final octet of an IPv4 address', function(string $ip, string $expected) {
    expect(Ip::anonymize($ip))->toBe($expected);
})->with([
    'public address' => ['203.0.113.45', '203.0.113.0'],
    'already zeroed' => ['203.0.113.0', '203.0.113.0'],
    'private address' => ['192.168.1.254', '192.168.1.0'],
    'loopback' => ['127.0.0.1', '127.0.0.0'],
]);

it('keeps only the /48 prefix of an IPv6 address', function(string $ip, string $expected) {
    expect(Ip::anonymize($ip))->toBe($expected);
})->with([
    'documentation address' => ['2001:db8:abcd:12::1', '2001:db8:abcd::'],
    'full-form address' => ['2001:0db8:abcd:0012:0000:0000:0000:0001', '2001:db8:abcd::'],
    'loopback' => ['::1', '::'],
]);

it('returns null for a missing address', function(?string $ip) {
    expect(Ip::anonymize($ip))->toBeNull();
})->with([
    'null' => [null],
    'empty' => [''],
]);

it('fails closed to null for an unparseable address', function(string $ip) {
    expect(Ip::anonymize($ip))->toBeNull();
})->with([
    'garbage' => ['not-an-ip'],
    'out-of-range octet' => ['203.0.113.999'],
    'trailing junk' => ['203.0.113.45 extra'],
]);
