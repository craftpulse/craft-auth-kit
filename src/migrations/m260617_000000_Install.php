<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Foundational authentication primitives for Craft.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

namespace craftpulse\authkit\migrations;

/**
 * m260617_000000_Install is the module-track wrapper around [[Install]].
 *
 * Craft's [[\craft\db\MigrationManager]] only discovers dated `mYYMMDD_HHMMSS_*`
 * files, so the base schema needs a dated name for `up()` to find it on the
 * `module:auth-kit` track — the plugin era's special-cased `Install` migration
 * has no such privileged slot on a module track. The date is Auth Kit 1.0.0's
 * release date, which sorts it before every later delta migration, exactly
 * matching the order the plugin era applied the same work in. All schema logic
 * stays in [[Install]] (which remains the canonical, idempotent schema owner);
 * this class only gives it a discoverable, correctly-ordered name.
 *
 * On plugin-era installs this never runs: [[Adoption::adoptFromPlugin()]]
 * marks it as applied when the tokens table already exists. On fresh installs
 * it runs first and the deltas after it are guarded no-ops.
 *
 * @author Michael Thomas
 * @since 1.7.0
 */
class m260617_000000_Install extends Install
{
}
