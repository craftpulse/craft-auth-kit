<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Schema tests for the registry's `isNewLocation` column. The column arrived in
 * 1.11.0 against a table most installs already carried, so it cannot come from
 * `Install`'s `CREATE` alone and has to be reachable by an upgrade path that is
 * both idempotent and reversible. The column's nullability is load-bearing, not
 * cosmetic: null is reserved for a row written before the flag existed, so a
 * consumer badging on the column never presents "never assessed" as "the
 * registry checked and the place was familiar".
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craft\db\Query;
use craft\db\Table as CraftTable;
use craft\helpers\Db;
use craft\helpers\StringHelper;
use craftpulse\authkit\db\Table;
use craftpulse\authkit\migrations\m260807_000002_AddSessionIsNewLocation;

/**
 * Returns whether the registry currently carries the column, always against a
 * freshly read schema — Craft memoizes table schemas, and every assertion here
 * follows a DDL statement.
 */
function isNewLocationColumnExists(): bool
{
    return Craft::$app->getDb()->columnExists(Table::SESSIONS, 'isNewLocation', true);
}

it('carries the isNewLocation column on the session registry', function() {
    expect(isNewLocationColumnExists())->toBeTrue();
});

it('keeps the column nullable, so an unassessed row is never read as not new', function() {
    $column = Craft::$app->getDb()->getTableSchema(Table::SESSIONS, true)?->getColumn('isNewLocation');

    expect($column)->not->toBeNull()
        ->and($column->allowNull)->toBeTrue()
        // No default either: a row must be written with an explicit answer, or
        // carry the null that says nobody asked.
        ->and($column->defaultValue)->toBeNull();
});

it('round-trips the column down and back up, and a second up adds nothing', function() {
    $migration = new m260807_000002_AddSessionIsNewLocation(['db' => Craft::$app->getDb()]);

    expect(isNewLocationColumnExists())->toBeTrue();

    $migration->safeDown();

    expect(isNewLocationColumnExists())->toBeFalse();

    $migration->safeUp();

    expect(isNewLocationColumnExists())->toBeTrue();

    // Replayed against a schema that already has it: a no-op, not a
    // duplicate-column error.
    $migration->safeUp();

    expect(isNewLocationColumnExists())->toBeTrue();
});

it('back-fills a row that predates the column with null, never with false', function() {
    $migration = new m260807_000002_AddSessionIsNewLocation(['db' => Craft::$app->getDb()]);
    $tokenHash = hash('sha256', 'backfill-' . bin2hex(random_bytes(16)));
    $userId = (int)(new Query())->select(['id'])->from(CraftTable::USERS)->scalar();

    // Not wrapped by the suite's transaction: the DDL below implicitly commits,
    // so this row is cleaned up by hand at the end.
    Db::insert(Table::SESSIONS, [
        'userId' => $userId,
        'tokenHash' => $tokenHash,
        'isNewLocation' => true,
        'dateCreated' => Db::prepareDateForDb(new DateTime('now', new DateTimeZone('UTC'))),
        'dateUpdated' => Db::prepareDateForDb(new DateTime('now', new DateTimeZone('UTC'))),
        'uid' => StringHelper::UUID(),
    ]);

    try {
        // The row now looks exactly like one written before 1.11.0: captured,
        // with the question never asked of it.
        $migration->safeDown();
        $migration->safeUp();

        $value = (new Query())
            ->select(['isNewLocation'])
            ->from(Table::SESSIONS)
            ->where(['tokenHash' => $tokenHash])
            ->scalar();

        expect($value)->toBeNull();
    } finally {
        Db::delete(Table::SESSIONS, ['tokenHash' => $tokenHash]);
    }
});

it('tolerates a down against a schema that never had the column', function() {
    $migration = new m260807_000002_AddSessionIsNewLocation(['db' => Craft::$app->getDb()]);

    $migration->safeDown();
    $migration->safeDown();

    expect(isNewLocationColumnExists())->toBeFalse();

    $migration->safeUp();

    expect(isNewLocationColumnExists())->toBeTrue();
});
