# Usage

Let's run through a passwordless sign-in from start to finish, as a consuming plugin would build it. Before we dive in, make sure your plugin has called `AuthKit::register()` and applied Auth Kit's migrations, as described in [Installation & Setup](../get-started/installation-setup.md).

## The flow

A passwordless sign-in has six steps:

1. A visitor submits their email address to your plugin's controller.
2. A single-use credential is generated, hashed, and stored with an expiry.
3. The credential is emailed, either as a link or as a short code.
4. The visitor returns, following the link or submitting the code to your verify route.
5. The credential is looked up, verified, and burned, resolving the user it belongs to.
6. The user is logged in and redirected.

Auth Kit takes care of steps 2, 3, and 5. It will be up to your plugin to nominate the routes, own the forms and the responses, and log the user in.

## 1. Register your routes

Auth Kit imposes no URLs. Your plugin registers the site routes, and tells Auth Kit which one the emailed link should point at.

```php
use craft\events\RegisterUrlRulesEvent;
use craft\web\UrlManager;
use yii\base\Event;

Event::on(
    UrlManager::class,
    UrlManager::EVENT_REGISTER_SITE_URL_RULES,
    static function(RegisterUrlRulesEvent $event): void {
        $event->rules['sign-in'] = 'my-plugin/auth/request';
        $event->rules['sign-in/verify'] = 'my-plugin/auth/verify';
    },
);
```

## 2. Issue the credential

Your controller takes the submitted address and asks Auth Kit for a magic link. Pass `origin` so the token is scoped to your plugin, and `route` so the emailed URL points at the route you just registered.

```php
use craftpulse\authkit\AuthKit;

public function actionRequest(): ?Response
{
    $this->requirePostRequest();

    $email = (string)$this->request->getBodyParam('email');
    $returnUrl = $this->request->getValidatedBodyParam('returnUrl');

    AuthKit::getInstance()->getTokens()->issueMagicLink($email, $returnUrl, [
        'origin' => 'my-plugin',
        'route' => 'sign-in/verify',
    ]);

    return $this->asSuccess(Craft::t('my-plugin', 'If that address has an account, a sign-in link is on its way.'));
}
```

`issueMagicLink()` returns whether a link was actually sent, and you should almost always ignore that return value. Responding differently for an address that exists and one that does not turns your sign-in form into an account-existence oracle. Respond identically either way, and let the visitor's inbox be the only place the difference shows up.

## 3. Consume the credential

Auth Kit appends the raw token to the verify URL under the `mlToken` query parameter, deliberately not `token`: Craft's web application reserves `token` for its own routed tokens and answers 400 to any request naming it with a value Craft did not issue.

```php
use craftpulse\authkit\AuthKit;
use craftpulse\authkit\services\Tokens;

public function actionVerify(): ?Response
{
    $rawToken = (string)$this->request->getQueryParam(Tokens::TOKEN_PARAM);

    $user = AuthKit::getInstance()->getTokens()->consumeMagicLink($rawToken, 'my-plugin');

    if ($user === null) {
        // Expired, already used, unknown, or not yours. One message covers all of them.
        return $this->asFailure(Craft::t('my-plugin', 'That sign-in link is no longer valid.'));
    }

    $duration = Craft::$app->getConfig()->getGeneral()->userSessionDuration;
    Craft::$app->getUser()->login($user, $duration);

    return $this->redirectToPostedUrl($user);
}
```

Pass the same `origin` you issued under. Origin scoping is strict in both directions: a token issued by your plugin is invisible to another consumer's verify route, and a token presented at the wrong consumer's route is refused and left unburned for its rightful one.

Consumption is atomic. The token is burned with a conditional update that only succeeds while it is still unconsumed, so a double-submit or two parallel requests can never log in twice off one link.

## 4. Record what happened

If your plugin wants an audit trail, hand Auth Kit an `AuthEvent` after the login succeeds. Whether anything persists it depends on which sinks are registered on the install, which is not your concern.

```php
use craftpulse\authkit\audit\AuthEvent;

AuthKit::getInstance()->getAudit()->record(new AuthEvent(
    name: AuthEvent::LOGIN_MAGIC_LINK,
    emitter: 'my-plugin',
    userId: $user->id,
));
```

See [Audit](audit.md) for the event vocabulary and the rules the payload has to follow.

## Where this example stops

This walkthrough hardcodes the origin string in two places, which is fine for one controller and gets fragile across a plugin. Put it on a constant. It also ignores the return of `issueMagicLink()` entirely, which is correct for a public sign-in form and wrong for an admin-triggered invite, where you do want to know whether anything was sent.

Rate limiting is not shown and is not optional. Auth Kit throttles per address across every channel including programmatic issuance, but per-IP limiting on the controller is yours to add, with core's `RateLimiter` filter. The two compound.

## Summary

So what does Auth Kit do to help with this overall process, rather than doing it yourself?

- Generates, hashes, stores, and expires the credential, so the raw secret never touches your database or your logs.
- Burns the credential atomically on consumption, so one link is one login even under a double-submit.
- Equalizes the timing of every failure branch, so an unknown address, a suspended one, and a wrong code are indistinguishable from outside.
- Throttles issuance per address, per consumer, across every channel.
- Re-checks that the target account is still active and not locked before handing you a user, so a stale link cannot log in behind a lockout.
- Scopes every token to its issuing consumer, so two plugins sharing an install never see or burn each other's tokens.
- Prunes expired tokens on Craft's own garbage-collection pass, so you never schedule cleanup.
- Ships editable system messages for the emails, so an install can rewrite the copy without touching your plugin.
