<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
 *
 * Schema regression tests for the Install migration. Standalone Pest harnesses
 * (and any other consumer whose plugin-install detection lags reality) can
 * re-invoke `safeUp()` directly against a database that already carries
 * `authkit_tokens` (see `tests/Bootstrap.php`). `_createTables()` already
 * guards on `tableExists()`, but the index and foreign-key steps must be
 * idempotent too, or a second invocation piles up duplicate, functionally
 * identical indexes and foreign keys with no error, until MySQL's
 * 64-key-per-table ceiling turns every subsequent install into a hard
 * failure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craft\helpers\Db;
use craftpulse\authkit\db\Table;
use craftpulse\authkit\migrations\Install;

/**
 * The baseline schema created by a single `safeUp()`: four `createIndex()`
 * calls (one of them unique) and one foreign key. The primary key itself
 * isn't reported by `Schema::findIndexes()`, which only matches secondary
 * `KEY` clauses in `SHOW CREATE TABLE`, not `PRIMARY KEY`.
 */
const AUTHKIT_TOKENS_BASELINE_INDEX_COUNT = 4;
const AUTHKIT_TOKENS_BASELINE_FK_COUNT = 1;

it('creates the authkit_tokens table on install', function() {
    expect(Craft::$app->getDb()->tableExists(Table::TOKENS))->toBeTrue();
});

it('is idempotent when safeUp() runs again against an already-installed schema', function() {
    $db = Craft::$app->getDb();

    // A prerequisite of the regression: the table must already exist before
    // safeUp() runs a second time, exactly like the real re-invocation path.
    expect($db->tableExists(Table::TOKENS))->toBeTrue();

    $migration = new Install(['db' => $db]);
    $migration->safeUp();

    $schema = $db->getSchema();
    $schema->refreshTableSchema(Table::TOKENS);

    $indexCount = count($schema->findIndexes(Table::TOKENS));

    expect($indexCount)->toBe(AUTHKIT_TOKENS_BASELINE_INDEX_COUNT);

    $fkCount = count($schema->getTableSchema(Table::TOKENS)?->foreignKeys ?? []);

    expect($fkCount)->toBe(AUTHKIT_TOKENS_BASELINE_FK_COUNT);
});

it('still enforces tokenHash uniqueness at the database level after a repeated safeUp()', function() {
    $db = Craft::$app->getDb();
    $schema = $db->getSchema()->getTableSchema(Table::TOKENS);

    expect($schema)->not->toBeNull();

    $uniqueIndexes = $db->getSchema()->findUniqueIndexes($schema);

    expect(array_values($uniqueIndexes))->toContain(['tokenHash']);
});

it('still has the userId foreign key to users after a repeated safeUp()', function() {
    expect(Db::findForeignKey(Table::TOKENS, ['userId'], Craft::$app->getDb()))->not->toBeNull();
});
