<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Pest configuration — binds craft-pest's TestCase AND its `RefreshesDatabase`
 * trait to every test in this suite. `TestCase` alone boots Craft but does NOT
 * wrap tests in a transaction; only `RefreshesDatabase` opens a transaction in
 * `setUp()` and rolls it back in `tearDown()` (see
 * `markhuot\craftpest\test\RefreshesDatabase`). Without it every factory
 * write in this suite committed permanently.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craft\enums\CmsEdition;
use markhuot\craftpest\test\RefreshesDatabase;
use markhuot\craftpest\test\TestCase;
use yii\caching\ArrayCache;

// Per-test in-memory cache: keeps throttle state isolated between tests and
// avoids the playground FileCache's filemtime() stat warnings.
uses(TestCase::class, RefreshesDatabase::class)
    ->beforeEach(function() {
        Craft::$app->set('cache', new ArrayCache());

        // Craft's own CmsEdition (Solo/Team/Pro/Enterprise) — a fresh install
        // against an empty test database has no project config specifying
        // system.edition, so it defaults to Solo, whose one-admin-only
        // getMaxUsers() cap (craft\services\Users::canCreateUsers()) silently
        // fails saveElement() — no validation error, just false — for every
        // test in this suite that creates an additional throwaway user, which
        // is most of them. Pinned to the ceiling here so no Craft-core
        // edition gate blocks a test that isn't actually testing that gate.
        // Scoped to this test's own transaction (rolled back in tearDown),
        // never a permanent change to the shared test database.
        Craft::$app->setEdition(CmsEdition::Enterprise);
    })
    ->in(__DIR__);
