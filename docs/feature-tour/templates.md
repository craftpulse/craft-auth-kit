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

The four token emails are editable system messages, not templates you override. An install rewrites the copy in the control panel under Settings, System Messages. See [Tokens](tokens.md) for the message keys and the variables each one renders with.
