# Tokens

The `tokens` service issues and consumes hashed, single-use, expiring passwordless credentials. Four kinds share one table, discriminated by type: magic links, email one-time codes, guest one-time codes, and registration links.

The raw secret is never persisted. Only its SHA-256 hash is stored, and the hash is what every lookup compares against. The raw value lives in the emailed link or code and nowhere else, which means a database dump is not a set of usable credentials and neither is a leaked backup.

## Origin

An origin is the consuming plugin's own label, at most 32 characters, stored on the token and matched strictly at consume time. It is how two plugins share one token table without sharing tokens.

Origin scoping is strict in both directions. A consumer passing its own origin only ever sees tokens issued under that origin, and a consume with no origin only sees tokens issued with no origin. A token presented at the wrong consumer's endpoint is refused, and left unburned for the endpoint it belongs to.

Warden issues under `warden` and Warp under `warp`, so a Warden magic link submitted to Warp's verify route fails and stays usable, rather than being silently consumed by a plugin that has no idea what to do with it. The per-address throttle is scoped the same way, so one consumer exhausting its budget for a mailbox never starves another.

Origin is an option on the login and registration issuances, and a required argument on the guest code, which only makes sense scoped to the consumer that issued it.

## Token type

Four types, and the difference between them is what the credential proves.

- **Magic link.** A 32-byte secret, emailed as a URL. Unguessable, so there is no attempt cap and the hash is the lookup key. Proves the holder controls a known user's mailbox, and resolves to that user.
- **Email OTP.** A short numeric code, emailed to a known user. Guessable, so it is attempt-capped, scoped to the user, and superseded whenever a new code is issued. Resolves to that user.
- **Guest OTP.** A short numeric code, emailed to any syntactically valid address whether or not it maps to a user. Proves mailbox control and nothing else. Resolves to a boolean.
- **Registration.** A 32-byte secret for an address with no account yet. Mints no user row. Proves mailbox control, and carries the address in its payload for you to act on.

## Payload

The payload is arbitrary issuance metadata carried on the token and handed back on consumption. Auth Kit puts the `returnUrl` there for magic links, and the target `email` plus any `returnUrl` there for registration links.

It is the only reason `consumeRegistration()` returns a token rather than a user: there is no user yet, and the payload's email is the fact the token proved.

## Subject

The subject is the lookup key for a guest code: the SHA-256 of the lowercased address. The raw email is never stored, so the token table cannot be mined for the addresses a guest flow has touched. Attribution of a guest verification is the consuming plugin's audit story, not Auth Kit's.

## Issuing and consuming

```php
use craftpulse\authkit\AuthKit;

$tokens = AuthKit::getInstance()->getTokens();

// Issue a magic link to a known, active user and email it as a verify URL.
$sent = $tokens->issueMagicLink($email, $returnUrl, ['origin' => 'my-plugin']);

// Consume a raw magic-link token and get the user to log in, or null.
$user = $tokens->consumeMagicLink($rawToken, 'my-plugin');

// Issue a one-time code to a known, active user, superseding any live code.
$sent = $tokens->issueOtp($email, ['origin' => 'my-plugin']);

// Consume a submitted code for an address and get the user to log in, or null.
$user = $tokens->consumeOtp($email, $code, 'my-plugin');

// Issue a one-time code to any valid mailbox, member or not. Reveals nothing.
$tokens->issueGuestOtp($email, 'my-plugin');

// Consume a guest code and get whether it proved control of the mailbox.
$proved = $tokens->consumeGuestOtp($email, $code, 'my-plugin');

// Issue a registration link to an address with no usable account yet.
$sent = $tokens->issueRegistration($email, $returnUrl, ['origin' => 'my-plugin']);

// Consume a registration token and get the burned token, or null.
$token = $tokens->consumeRegistration($rawToken, 'my-plugin');
$verifiedEmail = $token?->payload['email'] ?? null;

// Delete every expired token. Wired to Craft's garbage collection already.
$deleted = $tokens->purgeExpiredTokens();
```

The raw token arrives on your verify route under the `Tokens::TOKEN_PARAM` query parameter, whose value is `mlToken`. It is deliberately not `token`: Craft's web application reserves its `tokenParam` for routed tokens and answers 400 to any request naming it with a value Craft did not issue, so a magic link using `token` could never reach your controller.

## Issuance options

Every issuance takes an options array that overrides the shared service defaults for that one call. Use it rather than mutating the component, so two consumers on the same install never depend on each other's mutable singleton state.

| Option | Description |
|---|---|
| `origin` | The consuming plugin's label, 1 to 32 characters, stored on the token and matched strictly at consume time. |
| `route` | The site route the emailed verify URL is built against, for magic links and registration links. |
| `ttl` | The token lifetime in seconds, overriding `tokenTtl`. |
| `digits` | The number of digits in the code, for the two OTP issuances. |
| `maxAttempts` | The failed-attempt cap before the code is burned, for the two OTP issuances. |
| `perEmailLimit` | The number of issuances allowed to one address within the window. |
| `perEmailWindow` | The throttle window in seconds. |

Not every issuance accepts every option, and an option a call does not accept is an error rather than a value quietly ignored.

| Method | Accepts |
|---|---|
| `issueMagicLink()` | `origin`, `route`, `ttl`, `perEmailLimit`, `perEmailWindow` |
| `issueOtp()` | `origin`, `ttl`, `digits`, `maxAttempts`, `perEmailLimit`, `perEmailWindow` |
| `issueGuestOtp()` | `ttl`, `digits`, `maxAttempts`, `perEmailLimit`, `perEmailWindow` |
| `issueRegistration()` | `origin`, `route`, `ttl`, `perEmailLimit`, `perEmailWindow` |

An unknown key, a non-string `origin` or `route`, an origin outside 1 to 32 characters, or a non-positive integer for any of the numeric options throws an `InvalidArgumentException`. This is a security surface rather than a configuration grab-bag, so it fails loudly rather than falling back to a default. Note that `issueGuestOtp()` takes its origin as a required second argument, so passing `origin` in its options array is one of the keys that throws.

## Service defaults

The options above override these per call. To change them for the whole install, set them on the component through `config/app.php`.

| Property | Description |
|---|---|
| `tokenTtl` | The issued token lifetime in seconds. Defaults to 900. |
| `otpDigits` | The number of digits in an issued code. Defaults to 6. |
| `otpMaxAttempts` | The failed-attempt cap before a code is burned. Defaults to 5. |
| `perEmailLimit` | The issuances allowed to one address per window. Defaults to 5. |
| `perEmailWindow` | The throttle window in seconds. Defaults to 300. |
| `magicLinkRoute` | The default route the magic-link verify URL is built against. Defaults to `auth-kit/magic-link/verify`. |
| `registrationRoute` | The default route the registration verify URL is built against. Defaults to `auth-kit/registration/verify`. |
| `mailer` | The mailer used to deliver links and codes. Defaults to Craft's configured mailer. |

The two route defaults exist so the service has something to build a URL from. Auth Kit registers neither of them, so leaving them alone produces a link to a 404. Either register those exact routes in your plugin or pass your own `route` per issuance.

## Enumeration safety

The issuance methods return whether a credential was actually sent, and a public-facing caller must respond identically either way. That is the whole basis of an enumeration-safe endpoint, and it is the one contract Auth Kit cannot enforce for you.

Underneath, every refusal path is equalized. An unknown address, a suspended one, a locked one, a malformed one, and a wrong OTP code all pay the same fixed-cost verification before returning, so none of them is distinguishable from the happy path by timing. Registration inverts the eligibility test but mirrors the timing profile, so a unified sign-in and sign-up endpoint that routes a known address to `issueMagicLink()` and an unknown one to `issueRegistration()` gives nothing away in either branch.

`issueGuestOtp()` returns nothing at all, because there is nothing to reveal: any valid mailbox is issuable, so there is no account existence to hide.

## Throttling

Every issuance is throttled per address, per origin: at most `perEmailLimit` issuances within `perEmailWindow` seconds. The throttle covers every channel including programmatic issuance, which per-IP limiting at the controller does not.

The counter is a cache get followed by a cache set, which is not atomic, so racing parallel requests can overshoot the limit by a few. The overshoot is bounded by request concurrency, and the accepted trade is that Craft's cache interface has no portable atomic increment.

Add per-IP rate limiting on your controller with core's `RateLimiter` filter. The two limits compound, and neither substitutes for the other: per-IP stops one host hammering many addresses, per-address stops many hosts hammering one mailbox.

## Registration eligibility

`issueRegistration()` proceeds for an address with no usable account yet. That means an address Craft has never seen, and also a **pending** address whose holder can still finish activating through the signup link.

It refuses an address that maps to an active, suspended, or locked user. The refusal is equalized, so a caller cannot tell a taken address from a fresh one.

If your sign-in form dispatches between the two issuances, branch an active address to `issueMagicLink()` and everything else to `issueRegistration()`.

`consumeRegistration()` proves mailbox possession and nothing more. It returns the burned token, and the account decision is yours: create the user, activate a pending one, log them in, or hold the address for a later step. Auth Kit does not create user rows.

## Attempt caps and supersession

Magic links and registration links carry a 32-byte secret, so guessing one is not a threat model and they have no attempt cap.

Codes are short. Both OTP types are attempt-capped: a wrong code increments the counter with an atomic SQL increment, so racing parallel guesses cannot evade the cap, and once `maxAttempts` failures accrue the code is burned and every further attempt fails closed.

Issuing a new code supersedes any live unconsumed code for the same user, or the same mailbox for a guest code, within the same origin. Only the newest code is live, so an attacker cannot bank an old code's remaining attempt budget by requesting a fresh one.

## Account state

A login token is only honoured while its target account is genuinely usable. On consumption, after the token is burned, the user is re-checked: a suspended, deactivated, or locked account is refused.

The lock is checked explicitly, because Craft's `getStatus()` folds a locked account into "active". The token stays burned and the login is refused, mirroring the suspended path, so a stale link cannot be used to walk in behind a lockout.

## Emails

The four emails are editable system messages, so an install can rewrite the copy in the control panel without touching your plugin.

| Key | Description |
|---|---|
| `auth_kit_magic_link` | The magic-link email. Rendered with `link` and `user`. |
| `auth_kit_otp` | The one-time code email. Rendered with `code` and `user`. |
| `auth_kit_guest_otp` | The guest verification code email. Rendered with `code` and `email`. |
| `auth_kit_register` | The registration link email. Rendered with `link` and `email`. |

The guest and registration bodies address the visitor without a friendly name, because no user exists at that point.

The keys are available as constants on the service: `Tokens::MESSAGE_KEY_MAGIC_LINK`, `Tokens::MESSAGE_KEY_OTP`, `Tokens::MESSAGE_KEY_GUEST_OTP`, and `Tokens::MESSAGE_KEY_REGISTER`.

A delivery failure is logged and never surfaced. The token is already stored by then, and the response must not differ for the visitor.

## Cleanup

Expired tokens are deleted on Craft's garbage-collection pass, which Auth Kit hooks on registration. You do not need to schedule anything, and neither does the install. Expired tokens are already unusable, so there is no retention window to respect.

`purgeExpiredTokens()` is public if you want to run it yourself, and returns the number of rows deleted.
