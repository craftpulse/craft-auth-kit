# Requirements

## Craft CMS

Auth Kit requires Craft CMS 5.10.0 or greater.

The floor is 5.10.0 rather than 5.0.0 because the passkey wrappers call core's WebAuthn serializer, which only became public in 5.10.0. Anything your plugin does with tokens, passwords, or audit events would work on an earlier Craft 5, but the package as a whole does not, so declare the same floor in your own `composer.json`.

## PHP

Auth Kit requires PHP 8.2 or greater.

## Consumers

Auth Kit is consumed by a plugin, never installed on its own. A consuming plugin is responsible for:

- Registering the module. See [Installation & Setup](installation-setup.md).
- Applying Auth Kit's migrations from its own install migration.
- Owning every route, controller, form, and template. Auth Kit ships none.
- Deciding what to do with a consumed token: log a user in, create an account, mark an address verified.

## Mail

The token service sends magic links and one-time codes through Craft's configured mailer, using editable system messages. An install with no working mail transport can still issue tokens (the row is written and the raw secret is returned to nobody), but nothing will arrive. Delivery failures are logged and never surfaced to the visitor, because the response must not differ for an address that exists and one that does not.
