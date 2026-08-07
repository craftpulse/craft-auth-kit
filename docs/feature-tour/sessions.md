# Sessions & Locations

Craft's own `sessions` table stores a token and two timestamps. It has no idea what device produced a session, where from, or whether that somewhere is new. Auth Kit adds all three, in one place.

"One place" is the whole point. Two security plugins that each keep their own device registry give a member two device lists for one browser and two "new sign-in to your account" emails for one trip. Here there is one registry table, one location history, and one alert per place, whichever plugin happens to be watching.

Three services cooperate:

| Service | Owns |
|---|---|
| `sessions` | The device registry: one row per live Craft session, pinned to the device that produced it. |
| `locations` | The rule that decides whether a sign-in came from somewhere new, the shared history it reads, and the alert. |
| `geo` | Resolving a client IP to a coarse city and ISO country from a local database. |

## The device registry

Each row pins the sha256 hash of a Craft auth-session token to a truncated user-agent, an IP, the coarse location it was captured from, and whether that location was one the account had never been seen at. Only the hash is stored, never the token, so a leak of the registry yields nothing usable.

Capture is deliberately not wired for you. Your plugin decides when a login is registered and what its privacy settings say about the stored address:

```php
use craftpulse\authkit\AuthKit;
use craft\web\User as WebUser;
use yii\base\Event;

Event::on(WebUser::class, WebUser::EVENT_AFTER_LOGIN, function() {
    AuthKit::getInstance()->getSessions()->record([
        'anonymizeIp' => $this->getSettings()->anonymizeIp,
    ]);
});
```

`record()` is idempotent on the token hash, so it is safe for two plugins to wire it on the same install: whichever runs first writes the row and the other finds it already there. Call it from `EVENT_AFTER_LOGIN`, by which point Craft has generated the token and inserted its own row.

`anonymizeIp` defaults to `true`. The geo lookup always runs on the full address first, so the resolved location is the same either way; only the stored copy is coarsened (an IPv4 address loses its final octet, an IPv6 address keeps its /48 prefix).

Orphan pruning is wired by Auth Kit itself on `Gc::EVENT_RUN`, because the table belongs to Auth Kit. Logout pruning is yours, since only you know where your logout happens:

```php
Event::on(WebUser::class, WebUser::EVENT_BEFORE_LOGOUT, function() {
    $token = Craft::$app->getUser()->getToken();

    if ($token !== null) {
        AuthKit::getInstance()->getSessions()->pruneToken($token);
    }
});
```

### Reading and revoking

```php
$sessions = AuthKit::getInstance()->getSessions();

// One SessionInfo per live Craft session, current first, then most recent.
$list = $sessions->getSessionsForUser($user);

// Sign one device out. Scoped to the user in the query, so a posted uid can
// never reach another account's session.
$sessions->revoke($user, $uid, ['emitter' => 'my-plugin']);

// Sign out everything except the browser making this request.
$sessions->revokeOthers($user, ['emitter' => 'my-plugin']);
```

`SessionInfo` carries `uid`, `deviceLabel`, `deviceType`, `ip`, `city`, `isNewLocation`, `lastSeen`, and `isCurrent`. The `uid` is the registry row's, and is the only handle a front end ever posts back; the raw token is never exposed. A core session with no registry row (created before the registry existed, or by a path nobody captures) still appears, labelled "Unknown device" with a null `uid`, so nothing is hidden from the person managing their account. Those are revocable through `revokeOthers()` only.

Deleting the core `sessions` row is the authoritative kill: Craft validates the token against that table on every authenticated request, so the browser is a guest on its next one.

Both revocations record a `SESSION_REVOKED` audit fact with the `emitter` you pass. See [Audit](audit.md).

## New-location awareness

The rule is three lines of policy and easy to get subtly wrong, which is why it is shared:

- A login with no resolved country is never new. An install with no geo database therefore flags nothing and sends nothing.
- A user's first-ever sign-in is never new. There is no baseline, and telling somebody about the only place they have ever used is noise.
- Otherwise a location is new when no prior row for that user has this exact country and city.

```php
$locations = AuthKit::getInstance()->getLocations();

if ($locations->isNew($userId, $country, $city)) {
    $locations->alert($user, $country, $city, ['emitter' => 'my-plugin']);
}
```

`isNew()` reads the shared `authkit_locations` history by default. That history is written by `Sessions::record()`, so it covers every channel a member can sign in through, password included, not just the ones one plugin owns.

### The answer is stored, so you can badge and filter on it

You rarely need to call `isNew()` yourself for the shared history. `Sessions::record()` already asks it, once, and writes the answer to the registry row as `isNewLocation`, surfaced on `SessionInfo`. Two plugins badging a session-management screen therefore agree, because they are reading one stored fact rather than each recomputing it.

The order inside `record()` is load-bearing and worth knowing if you ever write a capture of your own: the question is asked **before** `seen()` files the place into the history. Reversed, the place is already there by the time you ask and the answer is always `false`.

`isNewLocation` is nullable, and null is not `false`:

| Value | Meaning |
|---|---|
| `true` | The account had been seen elsewhere before, and never here. |
| `false` | Asked and answered no: a repeat place, a first-ever sign-in (no baseline to be new against), or no country resolved. |
| `null` | Never asked. The row predates Auth Kit 1.11.0, or the core session has no registry row at all. |

Treat null as unknown. Rendering it as "not a new location" tells a member the registry checked when it never did.

If your plugin keeps a richer login log of its own and wants that as the baseline, hand `isNew()` a query over it. It needs `userId`, `country`, and `city` columns:

```php
$locations->isNew($userId, $country, $city, (new Query())->from('{{%myplugin_logins}}'));
```

### One alert, whoever spots it

`alert()` claims the location before it sends anything. The first caller stamps `dateAlerted` on the shared row and returns `true`; every later caller for the same user and place inside `alertWindow` (24 hours by default) returns `false` having done nothing. Two plugins that each independently decide the location is new still produce one audit fact and one email.

| Option | Description |
|---|---|
| `emitter` | Your plugin's handle, recorded against the audit fact. Defaults to `auth-kit`. |
| `messageKey` | The system message to compose from. Defaults to `authkit_new_location`. |
| `notify` | Whether to send the email at all. Defaults to `true`. |
| `sessionsUrl` | The link the copy points at. Defaults to the site URL. |

Pass `notify: false` when your own setting has member alerts turned off. The audit fact is still recorded: an install that does not email its members about a sign-in from a new country usually still wants it in the audit log.

Pass `messageKey` if your plugin already ships its own editable copy for this. An install that has customized those words would otherwise silently start receiving Auth Kit's generic version instead.

The default message, `authkit_new_location`, is editable under **Settings** → **Email** → **System Messages** and is rendered with `user`, `location`, `city`, `country`, and `sessionsUrl`.

## The geo database

Location awareness is optional and hangs off one file: a city-level MaxMind-format database at `storage/auth-kit/geo/city.mmdb`. One file for the whole install, so no two plugins download and maintain their own 65 MB copy.

With no database present, every lookup returns nulls, nothing is ever flagged, no alert is sent, and nothing errors. A project that does not want location awareness installs nothing and is done.

Install or refresh it with:

```shell
php craft auth-kit/geo/refresh
```

```shell
ddev craft auth-kit/geo/refresh
```

The download streams to a temp file and is renamed into place atomically, so a concurrent lookup never sees a partial database. Run it on deploy or on a schedule.

### Licence and attribution

The default download URL is a keyless mirror of MaxMind's **GeoLite2 City** database. GeoLite2 is free of charge but not public domain, and using it puts two obligations on you:

- **Attribution.** State, somewhere reasonable in your product or its documentation: "This product includes GeoLite2 data created by MaxMind, available from [https://www.maxmind.com](https://www.maxmind.com)."
- **Refresh at least every 30 days, destroying the copy you replace.** The GeoLite2 End User Licence Agreement does not permit retaining an outdated copy. `refresh()` overwrites in place, so a scheduled run satisfies both halves of that on its own; a database you install once and never touch again does not.

Both are conditions of the licence, not suggestions. If neither suits you, point the service at a differently licensed database from `config/app.php`:

```php
use craft\helpers\App;

return [
    'modules' => [
        'auth-kit' => [
            'class' => \craftpulse\authkit\AuthKit::class,
            'components' => [
                'geo' => ['databaseUrl' => App::env('GEO_DATABASE_URL')],
            ],
        ],
    ],
];
```

The reader handles both common record shapes, so a flat `country_code` / `city_name` database and a nested MaxMind `country.iso_code` / `city.names.en` one can both be dropped in.

A consuming plugin that exposes its own setting for the URL should subclass the service and override `getDatabaseUrl()` rather than write to the shared component, so two consumers never fight over one object.

## Privacy

The registry and the location history are personal data, held for account security. Both tables reference the user with an `ON DELETE CASCADE` foreign key, so deleting a user erases every row about them in the same operation, and an access request can be answered from the two tables filtered by the user's ID.

- The IP is read to derive a location and, by default, coarsened before it is stored.
- Location is a city name and a two-letter country code. No coordinates, and no member IP ever leaves the server: the lookup runs against the local database file.
- Device labels are not fingerprints. The user-agent is truncated and reduced to a coarse "Chrome on macOS" string for display. Two different phones can share a label, and the label never influences authorization.
- Registry rows die with the session they describe. The location history is one row per place, not per sign-in, so it stays proportional to how much a member travels rather than how often they sign in.
