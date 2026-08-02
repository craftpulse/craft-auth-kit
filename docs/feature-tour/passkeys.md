# Passkeys

The `passkeys` service exposes Craft's own WebAuthn machinery to front-end users, and enforces a recent-authentication gate on the operations that change a user's credentials.

Auth Kit re-implements no WebAuthn crypto. Creation options, attestation verification, and credential storage all run through core's `craft\services\Auth`, which is already conformance-tested. What Auth Kit adds is reach and a gate: core ships its passkey management behind a control-panel-only controller that a front-end user can never get to, and core's elevated-session check is useless to a user who has no password.

Passkey login is left to core's own anonymous endpoints. This service covers the operations a logged-in user performs on their own credentials.

## The API

```php
use craftpulse\authkit\AuthKit;

$passkeys = AuthKit::getInstance()->getPasskeys();

// Get the serialized creation options to hand to navigator.credentials.create().
$options = $passkeys->getCreationOptions($user);

// Verify an attestation response and store the credential. Gated.
$stored = $passkeys->verifyCreation($credentials, $credentialName);

// Get info about a user's saved passkeys.
$saved = $passkeys->getPasskeys($user);

// Get whether a user has any passkeys at all.
$has = $passkeys->hasPasskeys($user);

// Delete one of a user's passkeys by UID. Gated.
$removed = $passkeys->deletePasskey($user, $uid);

// Get whether the current session authenticated recently enough.
$recent = $passkeys->hasRecentAuth();

// Record the current session as having just authenticated.
$passkeys->stampRecentAuth();
```

`getCreationOptions()` returns a JSON string, ready to hand to the browser. Core stashes the matching options in the session for verification, so the enrollment and the verification have to happen in the same session.

`deletePasskey()` returns whether the user actually held a passkey with that UID. Core's delete is a silent no-op for an unknown UID, so the presence check happens here, and the return value is what keeps your audit trail factual: never record a deletion that did not happen. The check and the delete are not atomic, so two concurrent deletes of the same UID can both observe it as held and double-count one removal in a trail. Core's delete is itself idempotent and there is no authorization impact, so this is an accepted residual rather than a bug to work around.

## The recent-auth gate

Core gates sensitive operations behind `requireElevatedSession()`, which asks the user to re-enter their password. A passwordless user has no password to re-enter, so that gate can never be satisfied.

Auth Kit replaces it with a weaker but achievable question: did this session authenticate, by any means, within the last few minutes? The timestamp is stamped on every successful login, whatever the method, by a handler Auth Kit attaches when the module is registered. Magic link, one-time code, passkey, and password logins all refresh the window identically.

The default window is 300 seconds, mirroring core's `elevatedSessionDuration` default. Change it for the install through `config/app.php`:

```php
'modules' => [
    'auth-kit' => [
        'class' => \craftpulse\authkit\AuthKit::class,
        'components' => [
            'passkeys' => ['recentAuthDuration' => 120],
        ],
    ],
],
```

Or pass your own window per call, as the trailing `$within` argument on `hasRecentAuth()`, `verifyCreation()`, and `deletePasskey()`, when your plugin wants a tighter window than the install's default for one particular operation.

### The gate enforces itself

`verifyCreation()` and `deletePasskey()` check the gate themselves and throw a `yii\web\ForbiddenHttpException` when the session has not authenticated within the window. A caller that forgets to check cannot ship an ungated enrollment or deletion path.

That exception is a blunt response for a front-end user, so check first and handle it yourself:

```php
if (!$passkeys->hasRecentAuth()) {
    return $this->asFailure(Craft::t('my-plugin', 'Please sign in again to manage your passkeys.'));
}

$passkeys->deletePasskey($user, $uid);
```

### The gate authenticates the session, not the target

This is the part to get right. The gate asks whether the current session authenticated recently. It says nothing about whose credentials you are about to change. Authorization is scoped entirely by the `$user` argument you pass.

Always pass the authenticated user's own element:

```php
$user = Craft::$app->getUser()->getIdentity();
$passkeys->deletePasskey($user, $uid);
```

Never pass a user resolved from request input. A recently-authenticated session plus a user ID from a form parameter is an account takeover, and Auth Kit cannot tell the difference.

## Front-end wiring

For the browser side of enrollment and the `craft.authKit` Twig variable, see [Templates](templates.md).
