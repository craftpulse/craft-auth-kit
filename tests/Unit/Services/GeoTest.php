<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Service tests for optional geo enrichment: the record-shape extractors handle
 * both the flat ip-location-db and the nested MaxMind layouts, a lookup degrades
 * to nulls with no database present so it can never break the write it enriches,
 * the database resolves to one shared path for the whole install, and the
 * download URL is overridable both from config and from a subclass.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craftpulse\authkit\AuthKit;
use craftpulse\authkit\services\Geo;

it('reads the flat ip-location-db record shape', function() {
    $record = ['country_code' => 'be', 'city_name' => 'Brussels'];

    expect(Geo::countryFromRecord($record))->toBe('BE')
        ->and(Geo::cityFromRecord($record))->toBe('Brussels');
});

it('reads the nested MaxMind record shape', function() {
    $record = [
        'country' => ['iso_code' => 'JP'],
        'city' => ['names' => ['en' => 'Tokyo']],
    ];

    expect(Geo::countryFromRecord($record))->toBe('JP')
        ->and(Geo::cityFromRecord($record))->toBe('Tokyo');
});

it('returns null from an empty or malformed record', function() {
    expect(Geo::countryFromRecord(null))->toBeNull()
        ->and(Geo::cityFromRecord(null))->toBeNull()
        ->and(Geo::countryFromRecord(['country_code' => 'toolong']))->toBeNull()
        ->and(Geo::cityFromRecord(['city_name' => '']))->toBeNull();
});

it('degrades to nulls when no database is present', function() {
    $geo = new Geo();

    expect($geo->isAvailable())->toBeFalse()
        ->and($geo->lookup('8.8.8.8'))->toBe(['city' => null, 'country' => null])
        ->and($geo->lookup(null))->toBe(['city' => null, 'country' => null]);
});

it('resolves its database path under one shared storage folder', function() {
    expect((new Geo())->path())->toEndWith('auth-kit' . DIRECTORY_SEPARATOR . 'geo' . DIRECTORY_SEPARATOR . 'city.mmdb');
});

it('defaults to the GeoLite2 city database', function() {
    expect((new Geo())->getDatabaseUrl())->toBe(Geo::DEFAULT_DATABASE_URL)
        ->and(Geo::DEFAULT_DATABASE_URL)->toStartWith('https://');
});

it('takes its download URL from the component property', function() {
    $geo = new Geo();
    $geo->databaseUrl = 'https://example.test/city.mmdb';

    expect($geo->getDatabaseUrl())->toBe('https://example.test/city.mmdb');
});

it('lets a consumer subclass source the URL from its own settings', function() {
    $geo = new class() extends Geo {
        public function getDatabaseUrl(): string
        {
            return 'https://consumer.test/own.mmdb';
        }
    };

    expect($geo->getDatabaseUrl())->toBe('https://consumer.test/own.mmdb');
});

it('refuses to refresh with no URL configured', function() {
    $geo = new Geo();
    $geo->databaseUrl = '   ';

    expect(fn() => $geo->refresh())->toThrow(yii\base\Exception::class);
});

it('resolves through the module service accessor', function() {
    expect(AuthKit::getInstance()->getGeo())->toBeInstanceOf(Geo::class);
});
