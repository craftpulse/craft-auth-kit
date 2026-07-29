<?php
/**
 * Auth Kit plugin for Craft CMS 5.x
 *
 * Re-runnability regression tests covering EVERY migration this plugin ships,
 * not just `Install`. Guarding `Install` alone is what let the failure come
 * back: a later migration reintroduced a bare `createIndex(null, ...)` and a
 * bare `addForeignKey(null, ...)`, both of which name their object randomly and
 * are accepted again under a new name, so any context that replays a migration
 * (a lost migration history row, a manual `migrate/up`, a harness that
 * provisions the schema directly) silently accumulates duplicates until the
 * table crosses MySQL's 64-key-per-table ceiling and every subsequent install
 * fails outright.
 *
 * This file is the guard that would have caught the reintroduction: it replays
 * all four migrations against the already-migrated schema and asserts the index
 * and foreign-key inventory is byte-for-byte unchanged. Any new migration must
 * be added to the list below.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craft\db\Migration;
use craft\helpers\Db;
use craftpulse\authkit\db\Table;
use craftpulse\authkit\migrations\Install;
use craftpulse\authkit\migrations\m260711_000001_MakeTokenUserIdNullable;
use craftpulse\authkit\migrations\m260716_000001_AddTokenOrigin;
use craftpulse\authkit\migrations\m260718_000001_AddTokenSubject;

/**
 * Every migration Auth Kit ships, in application order.
 *
 * @var array<int, class-string<Migration>>
 */
const AUTHKIT_MIGRATION_CLASSES = [
    Install::class,
    m260711_000001_MakeTokenUserIdNullable::class,
    m260716_000001_AddTokenOrigin::class,
    m260718_000001_AddTokenSubject::class,
];

/**
 * Returns the current index inventory for `authkit_tokens`, keyed by index name.
 *
 * @return array<string, array{columns: array<int, string>, unique: bool}>
 */
function authKitTokenIndexes(): array
{
    $schema = Craft::$app->getDb()->getSchema();
    $schema->refreshTableSchema(Table::TOKENS);

    return $schema->findIndexes(Table::TOKENS);
}

/**
 * Returns the current foreign-key inventory for `authkit_tokens`, keyed by
 * constraint name.
 *
 * @return array<string, array<string, string>>
 */
function authKitTokenForeignKeys(): array
{
    $schema = Craft::$app->getDb()->getSchema();
    $schema->refreshTableSchema(Table::TOKENS);

    return $schema->getTableSchema(Table::TOKENS)?->foreignKeys ?? [];
}

it('carries exactly one index per indexed column set', function() {
    $columnSets = array_map(
        static fn(array $index): string => implode(',', $index['columns']) . ($index['unique'] ? ':unique' : ''),
        authKitTokenIndexes(),
    );

    // Duplicates are functionally identical indexes living under different
    // random names, which is precisely what an unguarded createIndex() leaves
    // behind and what no error ever surfaces.
    expect(array_values($columnSets))->toBe(array_values(array_unique($columnSets)));
});

it('adds no index and no foreign key when every migration is replayed against an already-migrated schema', function() {
    $db = Craft::$app->getDb();

    // A prerequisite of the regression: the schema must already be in place
    // before the migrations run again, exactly like the real replay path.
    expect($db->tableExists(Table::TOKENS))->toBeTrue();

    $indexesBefore = authKitTokenIndexes();
    $foreignKeysBefore = authKitTokenForeignKeys();

    foreach (AUTHKIT_MIGRATION_CLASSES as $class) {
        /** @var Migration $migration */
        $migration = new $class(['db' => $db]);
        $migration->safeUp();
    }

    expect(authKitTokenIndexes())->toBe($indexesBefore);
    expect(authKitTokenForeignKeys())->toBe($foreignKeysBefore);
});

it('restores a missing subject index when the column survived a partial application', function() {
    $db = Craft::$app->getDb();

    // The partial-application state: the column landed, the index did not. This
    // is reachable for real when a run dies between the two statements, and it
    // is the state the original migration could never recover from, because the
    // index creation sat inside the column's own existence guard.
    Db::dropIndexIfExists(Table::TOKENS, ['subject'], false, $db);

    expect($db->columnExists(Table::TOKENS, 'subject'))->toBeTrue();

    $indexedColumnSets = array_map(
        static fn(array $index): array => $index['columns'],
        authKitTokenIndexes(),
    );

    expect(array_values($indexedColumnSets))->not->toContain(['subject']);

    $migration = new m260718_000001_AddTokenSubject(['db' => $db]);
    $migration->safeUp();

    $restored = array_filter(
        authKitTokenIndexes(),
        static fn(array $index): bool => $index['columns'] === ['subject'],
    );

    // Exactly one: recovered, and not doubled by the recovery.
    expect($restored)->toHaveCount(1);

    // A second pass must not add another one.
    $migration->safeUp();

    $afterReplay = array_filter(
        authKitTokenIndexes(),
        static fn(array $index): bool => $index['columns'] === ['subject'],
    );

    expect($afterReplay)->toHaveCount(1);
});

it('leaves the schema fully usable after a replay', function() {
    $db = Craft::$app->getDb();
    $tableSchema = $db->getSchema()->getTableSchema(Table::TOKENS, true);

    expect($tableSchema)->not->toBeNull();

    // The three guarantees the guarded migrations must not have traded away:
    // tokenHash uniqueness, a nullable userId, and the indexed subject column
    // the guest OTP lookup depends on.
    expect(array_values($db->getSchema()->findUniqueIndexes($tableSchema)))->toContain(['tokenHash']);
    expect($tableSchema->getColumn('userId')?->allowNull)->toBeTrue();

    $indexedColumnSets = array_map(
        static fn(array $index): array => $index['columns'],
        authKitTokenIndexes(),
    );

    expect(array_values($indexedColumnSets))->toContain(['subject']);
});
