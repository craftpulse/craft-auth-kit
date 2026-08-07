<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Garbage collection is the one thing Auth Kit runs on its own initiative, and a
 * module's tables only exist once some consumer's migration has brought them up.
 * An install carrying this release alongside a consumer that has not adopted it
 * yet therefore has the pruning code without the table it prunes, and must not
 * start throwing on every `craft gc`.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craftpulse\authkit\db\Table;
use craftpulse\authkit\services\Sessions;

it('prunes nothing, quietly, when no consumer has created the registry yet', function() {
    $db = Craft::$app->getDb();
    $schema = $db->getSchema();
    $renamed = '{{%authkit_sessions_hidden}}';

    // Renaming stands in for "never created": the rows survive, so the rest of
    // the suite is unaffected either way.
    $db->createCommand()->renameTable(Table::SESSIONS, $renamed)->execute();
    $schema->refresh();

    try {
        expect((new Sessions())->pruneOrphans())->toBe(0);
    } finally {
        $db->createCommand()->renameTable($renamed, Table::SESSIONS)->execute();
        $schema->refresh();
    }
});
