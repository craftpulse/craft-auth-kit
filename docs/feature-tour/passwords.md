# Passwords

The `passwords` service is a neutral cooperation seam for password strength and breach checks. A consumer calls it on any set-password or registration flow; a provider registers a validator that implements the checking. Neither side knows the other exists.

This is the point of the contract. Plugins cooperate through the registry, never by sniffing each other with `isPluginInstalled()`. A consumer calls `validate()` unconditionally and gets a valid verdict on an install where nothing is registered, so the call site never branches on which plugins happen to be present.

## Validating a password

```php
use craftpulse\authkit\AuthKit;

$result = AuthKit::getInstance()->getPasswords()->validate($password, $user);

if (!$result->isValid) {
    foreach ($result->errors as $error) {
        $model->addError('password', $error);
    }
}
```

`validate()` runs every registered validator and returns the aggregate verdict: invalid if any validator rejected, with all of their error messages collected. The `$user` argument is optional and passed through to every validator, which lets a policy reject a password that contains the user's own username or reuses one of their previous passwords.

With no validator registered, `validate()` is a graceful no-op and every password is valid.

`PasswordValidationResult` is a plain value object with exactly two readonly properties, `isValid` and `errors`, and two factories, `valid()` and `invalid($errors)`. Its shape is frozen at 1.0.0. It is deliberately not a `craft\base\Model`, because `$errors` on a Model would shadow Yii's inherited `getErrors()` validation API and leave two same-named APIs answering different questions.

## Registering a validator

A provider plugin ships a class implementing `craftpulse\authkit\passwords\PasswordValidatorInterface`:

```php
use craft\elements\User;
use craftpulse\authkit\passwords\PasswordValidationResult;
use craftpulse\authkit\passwords\PasswordValidatorInterface;

class MyPolicyValidator implements PasswordValidatorInterface
{
    public function validate(string $password, ?User $user): PasswordValidationResult
    {
        if (strlen($password) < 12) {
            return PasswordValidationResult::invalid([
                Craft::t('my-plugin', 'Password must be at least 12 characters.'),
            ]);
        }

        return PasswordValidationResult::valid();
    }
}
```

and registers it from its own `init()`:

```php
use craftpulse\authkit\events\RegisterPasswordValidatorsEvent;
use craftpulse\authkit\services\Passwords;
use yii\base\Event;

Event::on(
    Passwords::class,
    Passwords::EVENT_REGISTER_PASSWORD_VALIDATORS,
    function(RegisterPasswordValidatorsEvent $event) {
        $event->validators[] = new MyPolicyValidator();
    }
);
```

The interface is one method. Keep the adapter thin: it exists to translate your plugin's own strength or breach logic into the neutral verdict, not to hold that logic.

## Reading and replacing the registry

```php
use craftpulse\authkit\AuthKit;

$passwords = AuthKit::getInstance()->getPasswords();

// Get the registered validators, assembling them from the event on first access.
$validators = $passwords->getValidators();

// Replace the registry outright.
$passwords->setValidators([]);
```

The registry is assembled lazily on first access, so a listener attached after something has already called `validate()` will not be picked up. Register in `init()`.

`setValidators()` is for tests and explicit wiring. Use it to silence policy in a suite that is testing something else, and use the event for everything else. Runtime registration through the event is what lets two provider plugins coexist; `setValidators()` replaces whatever the other one contributed.

## Stability

The interface is deliberately tiny, and both it and `PasswordValidationResult` are frozen. Treat any change to either as a major version bump, and write adapters against them accordingly.
