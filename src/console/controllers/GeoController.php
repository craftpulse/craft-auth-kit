<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\console\controllers;

use craftpulse\authkit\AuthKit;
use Throwable;
use yii\console\Controller;
use yii\console\ExitCode;
use yii\helpers\Console;

/**
 * Installs and refreshes the shared city geo database.
 *
 * Location awareness is optional, and all of it hangs off one file: a
 * city-level MaxMind-format database that every consuming plugin reads from
 * one shared path under Craft's storage directory. Run auth-kit/geo/refresh on
 * deploy or on a schedule to install or update it.
 *
 * The default download URL is a keyless mirror of MaxMind's GeoLite2 City
 * database. GeoLite2 is free but not public domain: crediting MaxMind and
 * refreshing at least every 30 days (destroying the copy you replace) are
 * conditions of using it. Refreshing overwrites in place, so a scheduled run
 * satisfies both halves. Point the geo component's databaseUrl elsewhere in
 * config/app.php to use a differently licensed database.
 *
 * With no database installed everything degrades silently: no location, no
 * new-location detection, no alerts. A project that does not want location
 * awareness leaves this command unrun.
 *
 * @author CraftPulse
 * @since 1.10.0
 */
class GeoController extends Controller
{
    // Public Methods
    // =========================================================================

    /**
     * Downloads a fresh city database from the configured URL and installs it, replacing any current database.
     *
     * @return int a `yii\console\ExitCode` value
     *
     * @author CraftPulse
     * @since 1.10.0
     */
    public function actionRefresh(): int
    {
        try {
            AuthKit::getInstance()->getGeo()->refresh();
        } catch (Throwable $e) {
            $this->stderr('Could not refresh the geo database: ' . $e->getMessage() . PHP_EOL, Console::FG_RED);

            return ExitCode::UNSPECIFIED_ERROR;
        }

        $this->stdout('Geo database refreshed.' . PHP_EOL, Console::FG_GREEN);

        return ExitCode::OK;
    }
}
