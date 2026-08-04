# Templates

Auth Kit ships no templates and registers no routes. What it does give the front end is one Twig variable and one browser client script, both aimed at the passkey management UI a consuming plugin builds.

## `craft.authKit`

| Variable | Description |
|---|---|
| `craft.authKit.hasPasskeys()` | Returns whether the current user has any passkeys enrolled. Returns false for a guest. |
| `craft.authKit.passkeys()` | Returns the current user's saved passkeys, or an empty array for a guest. |
| `craft.authKit.webauthnJsUrl()` | Returns the published URL of the reference WebAuthn client script. |

The variable resolves the current user itself, so there is no user argument on any of the three. Templates never get a handle on another user's credentials through it.

```twig
{% if craft.authKit.hasPasskeys() %}
    <ul>
        {% for passkey in craft.authKit.passkeys() %}
            <li>{{ passkey.credentialName }}</li>
        {% endfor %}
    </ul>
{% else %}
    <p>{{ 'You have no passkeys yet.'|t('my-plugin') }}</p>
{% endif %}
```

The passkey entries come straight from Craft's own `Auth::getPasskeys()`, so their shape is core's, not Auth Kit's. Each one is an array carrying `credentialName`, `dateLastUsed`, and `uid`. The `uid` is what you pass back to `deletePasskey()`.

## The WebAuthn client

Auth Kit publishes a shared browser client, `authkit-webauthn.js`, and `webauthnJsUrl()` returns its published URL:

```twig
<script src="{{ craft.authKit.webauthnJsUrl() }}"></script>
```

It is a reference client, not a framework. It covers the browser half of enrollment: taking the serialized creation options from `getCreationOptions()`, calling `navigator.credentials.create()`, and posting the attestation response back. Everything around it, the form, the endpoints, the error handling, and the styling, belongs to your plugin.

If you already have a WebAuthn client, or your front end has a build step that would rather import one, ignore this script entirely. Nothing else in Auth Kit depends on it.

## Emails

The four token emails are Craft system messages, not templates you override. See [Tokens](tokens.md#emails) for the message keys and the variables each one renders with.

They behave exactly like Craft's own transactional emails (account activation, password reset), which gives an install three independent levers: the copy, its translations, and the HTML the copy lands in.

### Editing the copy

The messages are editable in the control panel under Utilities, then System Messages. Craft registers that screen on Pro and above; below Pro every install gets the shipped copy.

Each message lists its heading, subject, and body. Subject and body are Twig, and the body is parsed as Markdown, so a rewritten body can use the variables the message renders with and can carry links and emphasis. On a multi-site install the edit screen carries a language switcher, and the copy is stored per language.

A saved edit replaces the shipped default for that message and that language from then on. Two things follow. Keep the variables you still want when you rewrite a body, `{{ link }}`, `{{ code }}`, and `{{ expiresIn }}` in particular, because nothing re-adds them. And an edited message no longer follows the default copy, so a later Auth Kit release that improves the wording of a message you have rewritten leaves your version alone.

### Translating the defaults

The defaults go through the `auth-kit` translation category, which the module registers itself and which accepts site overrides. To supply another language, add `translations/<language>/auth-kit.php` in the project, keyed on the English source string:

```php
<?php

return [
    'Your sign-in link' => 'Uw aanmeldlink',
    'Your sign-in code' => 'Uw aanmeldcode',
];
```

Which language an email renders in follows the request: on a front-end request it is the current site's language, and on a console or queue request it is the primary site's language. Auth Kit addresses the mailbox by email address rather than by user, so a recipient's own preferred language does not come into it. This is deliberate, since an issuance is anonymous by design and the address need not belong to an account at all.

A control-panel edit is already per language, so on a multi-site install you can use either lever, or both: edited copy wins for the languages you edit, translated defaults cover the rest.

### Styling them

Delivery goes through Craft's own `composeFromKey()` pipeline, so these emails are styled by the same setting as every other Craft email: Settings, then Email, then HTML Email Template (Craft Pro). Point it at a site Twig template and all four render inside your wrapper.

The wrapper receives `body`, the message's parsed Markdown as ready-to-print HTML, plus the variables the message body gets, in case the wrapper wants them. Without a template set, or below Pro, Craft uses its own plain wrapper. Either way Craft keeps generating the plain-text alternative.

Nothing about this is Auth Kit configuration: if a consuming plugin's own emails already render inside a site's wrapper, these do too.
