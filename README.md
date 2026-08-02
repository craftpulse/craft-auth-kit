# Auth Kit

Auth Kit is the foundational authentication package for Craft CMS 5, giving plugins passwordless tokens, passkey wrappers, a recent-authentication gate, and neutral contracts for password validation and audit logging.

Auth Kit is a library-shipped Yii module, not a Craft plugin. It has no Plugin Store entry, never appears in Craft's installed-plugins list, and adds nothing to the control panel. It is written for developers building plugins that consume it.

## Features

- Passwordless magic links, backed by hashed, single-use, expiring tokens.
- Email one-time codes, attempt-capped and superseded whenever a new code is issued.
- Guest one-time codes that prove control of any mailbox without creating a user.
- Registration links for addresses that have no account yet.
- Passkey enrollment, listing, and deletion for front-end users, wrapping Craft's own WebAuthn machinery.
- A recent-authentication gate, the passwordless replacement for elevated sessions.
- A password-validator contract any plugin can implement, with no plugin detection on either side.
- An audit-event contract that carries authentication facts to any registered sink.
- One shared token table, owned once and migrated on Auth Kit's own track however many consumers share an install.

## Requirements

### Craft CMS

Auth Kit requires Craft CMS 5.10.0 or greater.

### PHP

Auth Kit requires PHP 8.2 or greater.

## Installation

Auth Kit is a package rather than a plugin, so there is no Plugin Store entry and no `plugin/install` step. Your plugin requires it and registers it at runtime.

1. Open your terminal and go to your plugin:

```shell
cd /path/to/plugin
```

2. Tell Composer to require the package:

```shell
composer require craftpulse/craft-auth-kit
```

You can also add it to your plugin's `composer.json` directly:

```json
"require": {
    "craftcms/cms": "^5.10.0",
    "craftpulse/craft-auth-kit": "^1.7.0"
}
```

### DDEV

If your project runs in DDEV, run the same command through DDEV from the project root:

```shell
ddev composer require craftpulse/craft-auth-kit
```

Requiring the package does not wire it up. See [Installation & Setup](docs/get-started/installation-setup.md) for the two calls your plugin needs to make.

## Documentation

Full documentation is in [docs/](docs/README.md).

## Licensing

Auth Kit is released under the MIT license. See [LICENSE.md](LICENSE.md).

## Support

Report a bug or request a feature on the [issue tracker](https://github.com/craftpulse/craft-auth-kit/issues).

For anything else, email [support@craft-pulse.com](mailto:support@craft-pulse.com).
