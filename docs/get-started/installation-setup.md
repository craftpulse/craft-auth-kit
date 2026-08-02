# Installation & Setup

## Installation

Auth Kit is a library package, not a Craft plugin. There is no Plugin Store entry and no `plugin/install` step. You add the package to your project using Composer, or as a requirement in your plugin's `composer.json` file directly:

```shell
composer require craftpulse/craft-auth-kit
```

```json
"require": {
    "craftcms/cms": "^5.10.0",
    "craftpulse/craft-auth-kit": "^1.7.0"
}
```

If your project runs in DDEV, run the same command through DDEV from the project root:

```shell
ddev composer require craftpulse/craft-auth-kit
```

## Setup

To use Auth Kit in your plugin, call the idempotent `AuthKit::register()` from your plugin's `init()`, then reach any service you need through `AuthKit::getInstance()`.

```php
use craftpulse\authkit\AuthKit;

public function init(): void
{
    parent::init();

    AuthKit::register();

    // ...
}
```

Registration is what makes Auth Kit work, and nothing calls it for you. Requiring the package alone leaves the module unregistered: no expired-token garbage collection, no recent-auth stamping on login, no system messages, and no `craft.authKit` Twig variable.

The first call creates the module, sets it on the application under the `auth-kit` module ID, and attaches Auth Kit's event handlers. Every later call returns the same instance and does nothing else, so any number of consumers can each call it. On an install running both Warp and Warden, both plugins call `register()` in their own `init()` and the second call is a no-op.

Two accessors are available everywhere, including inside migrations and console commands:

```php
// Always safe. Registers the module first if no consumer has yet.
AuthKit::getInstance()->getTokens();

// Shorthand, available once any consumer has registered the module.
AuthKit::$plugin->getTokens();
```

Prefer `getInstance()` in migrations and anywhere the registration order is not obvious. Prefer `AuthKit::$plugin` in request-time code inside your own plugin, where your `init()` has already run.

### Migrations

Auth Kit stores tokens in its own database table, shared by every consuming plugin, so your plugin has to make sure Auth Kit's migrations have run. In your plugin's `migrations/Install.php` file, add the following:

```php
class Install extends \craft\db\Migration
{
    public function safeUp(): bool
    {
        // Ensure that Auth Kit kicks off setting up its tables
        \craftpulse\authkit\AuthKit::getInstance()->getMigrator()->up();

        // Create any tables that your plugin requires
        $this->createTables();

        return true;
    }
}
```

This creates Auth Kit's database tables if they do not already exist from another plugin requiring it, ready for you to issue tokens against. Applied migrations are recorded on Auth Kit's own `module:auth-kit` track, so a second consumer's install finds nothing left to do.

If you are including this in a module rather than a plugin, you will not be able to make use of the `migrations/Install.php` migration that plugins have access to. Instead, call it through a content migration.

### Keeping the schema current

Auth Kit has no plugin schema version for Craft to watch, so a release that adds a migration is not picked up on its own. When you raise your Auth Kit requirement to a release whose changelog lists a new migration, ship a dated migration of your own containing the same line:

```php
public function safeUp(): bool
{
    \craftpulse\authkit\AuthKit::getInstance()->getMigrator()->up();

    return true;
}
```

This keeps Auth Kit's schema changes on your plugin's own upgrade path, where they run as part of the `craft up` your users already expect, rather than on an implicit one they cannot see. It costs you one file per Auth Kit release that changes the schema, and most releases do not.

If the install you are upgrading carried Auth Kit 1.6.x or earlier as a Craft plugin, you need a one-time adoption migration instead. See [Upgrading from the Plugin Era](upgrading.md).

## Configuration

Auth Kit has no settings model and no settings screen. Its services are tuned by setting properties on the components, which an install does through `config/app.php`:

```php
'modules' => [
    'auth-kit' => [
        'class' => \craftpulse\authkit\AuthKit::class,
        'components' => [
            'tokens' => ['tokenTtl' => 600],
        ],
    ],
],
```

Declare only the components you are overriding. Auth Kit fills in the rest, so the three services this example never mentions are still there and still default.

Configuration is the consuming plugin's job as much as the install's. If your plugin exposes its own settings for token lifetime or code length, pass them per issuance through the options array rather than mutating the shared component, so two consumers on the same install never fight over one object. See [Tokens](../feature-tour/tokens.md).
