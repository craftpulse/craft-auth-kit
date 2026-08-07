<?php
/**
 * Auth Kit module for Craft CMS 5.x
 *
 * Service tests for new-location awareness. The matrix pins the rule (a
 * first-ever sign-in is never new, an unresolvable IP is never new, an exact
 * country-and-city match is never new), the consumer-supplied history override
 * that lets a plugin keep its own baseline, and the claim that makes two
 * consumers on one install send one email instead of two.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2026 CraftPulse
 */

use craft\db\Query;
use craft\elements\User;
use craft\helpers\Db;
use craft\helpers\StringHelper;
use craftpulse\authkit\audit\AuthEvent;
use craftpulse\authkit\AuthKit;
use craftpulse\authkit\db\Table;
use craftpulse\authkit\records\Location as LocationRecord;
use craftpulse\authkit\services\Locations;
use craftpulse\authkit\tests\Support\CollectingAuditSink;
use craftpulse\authkit\tests\Support\CollectingMailer;

function locationsUser(): User
{
    $unique = str_replace('-', '', StringHelper::UUID());
    $user = new User();
    $user->username = "loc-{$unique}@authkit-test.example";
    $user->email = "loc-{$unique}@authkit-test.example";

    if (!Craft::$app->getElements()->saveElement($user)) {
        throw new RuntimeException('Could not save locations test user.');
    }

    Craft::$app->getUsers()->activateUser($user);

    return Craft::$app->getUsers()->getUserById((int)$user->id);
}

function locationRow(int $userId, string $country, ?string $city): ?LocationRecord
{
    /** @var LocationRecord|null $record */
    $record = LocationRecord::findOne(['userId' => $userId, 'country' => $country, 'city' => $city]);

    return $record;
}

function withCollectingMailer(callable $body): CollectingMailer
{
    $mailer = new CollectingMailer();
    $original = Craft::$app->getMailer();
    Craft::$app->set('mailer', $mailer);

    try {
        $body();
    } finally {
        Craft::$app->set('mailer', $original);
    }

    return $mailer;
}

afterEach(function() {
    foreach (User::find()->email('*@authkit-test.example')->status(null)->all() as $user) {
        Craft::$app->getElements()->deleteElement($user, true);
    }

    AuthKit::$plugin->getAudit()->setSinks([]);
});

// =============================================================================
// the rule
// =============================================================================

it('never flags a location when no country could be resolved', function() {
    $user = locationsUser();
    $service = new Locations();
    $service->seen((int)$user->id, 'BE', 'Brussels');

    expect($service->isNew((int)$user->id, null, null))->toBeFalse()
        ->and($service->isNew((int)$user->id, null, 'Brussels'))->toBeFalse();
});

it('never flags a first-ever sign-in, because there is no baseline', function() {
    $user = locationsUser();

    expect((new Locations())->isNew((int)$user->id, 'JP', 'Tokyo'))->toBeFalse();
});

it('never flags a repeat sign-in from a place already in the history', function() {
    $user = locationsUser();
    $service = new Locations();
    $service->seen((int)$user->id, 'BE', 'Brussels');

    expect($service->isNew((int)$user->id, 'BE', 'Brussels'))->toBeFalse();
});

it('flags a place the user has never signed in from once a baseline exists', function() {
    $user = locationsUser();
    $service = new Locations();
    $service->seen((int)$user->id, 'BE', 'Brussels');

    expect($service->isNew((int)$user->id, 'JP', 'Tokyo'))->toBeTrue()
        ->and($service->isNew((int)$user->id, 'BE', 'Antwerp'))->toBeTrue();
});

it('keeps one user history out of another user history', function() {
    $alice = locationsUser();
    $bob = locationsUser();
    $service = new Locations();
    $service->seen((int)$alice->id, 'BE', 'Brussels');

    // Bob has no history at all, so nothing of his is ever new yet.
    expect($service->isNew((int)$bob->id, 'JP', 'Tokyo'))->toBeFalse();

    $service->seen((int)$bob->id, 'JP', 'Tokyo');

    // Alice being in Brussels says nothing about whether Bob has been there.
    expect($service->isNew((int)$bob->id, 'BE', 'Brussels'))->toBeTrue();
});

it('reads a consumer supplied history instead of the shared one', function() {
    $user = locationsUser();
    $service = new Locations();

    // The shared history says the user has only ever been in Brussels...
    $service->seen((int)$user->id, 'BE', 'Brussels');

    // ...but a consumer keeping its own log says they have been to Tokyo, and
    // its own log is what the rule reads when it is handed one.
    $history = (new Query())->from(Table::LOCATIONS)->andWhere(['country' => 'JP']);

    expect($service->isNew((int)$user->id, 'BE', 'Brussels', $history))->toBeFalse()
        ->and($service->isNew((int)$user->id, 'JP', 'Tokyo', $history))->toBeFalse();

    $service->seen((int)$user->id, 'JP', 'Tokyo');

    expect($service->isNew((int)$user->id, 'BE', 'Brussels', $history))->toBeTrue();
});

// =============================================================================
// history
// =============================================================================

it('records one row per place, however many sign-ins arrive from it', function() {
    $user = locationsUser();
    $service = new Locations();

    $service->seen((int)$user->id, 'BE', 'Brussels');
    $service->seen((int)$user->id, 'BE', 'Brussels');
    $service->seen((int)$user->id, 'BE', 'Brussels');

    $count = (new Query())
        ->from(Table::LOCATIONS)
        ->where(['userId' => (int)$user->id, 'country' => 'BE', 'city' => 'Brussels'])
        ->count();

    expect((int)$count)->toBe(1);
});

it('records a country-only resolution as its own place', function() {
    $user = locationsUser();
    $service = new Locations();

    $service->seen((int)$user->id, 'BE', null);
    $service->seen((int)$user->id, 'BE', 'Brussels');

    expect(locationRow((int)$user->id, 'BE', null))->not->toBeNull()
        ->and(locationRow((int)$user->id, 'BE', 'Brussels'))->not->toBeNull();
});

it('records nothing for an unresolvable location', function() {
    $user = locationsUser();
    (new Locations())->seen((int)$user->id, null, 'Brussels');

    $count = (new Query())->from(Table::LOCATIONS)->where(['userId' => (int)$user->id])->count();

    expect((int)$count)->toBe(0);
});

// =============================================================================
// alerting — claimed once across every consumer
// =============================================================================

it('emails the member and records the audit fact on the first alert', function() {
    $user = locationsUser();
    $sink = new CollectingAuditSink();
    AuthKit::$plugin->getAudit()->setSinks([$sink]);
    $claimed = null;

    $mailer = withCollectingMailer(function() use ($user, &$claimed) {
        $claimed = (new Locations())->alert($user, 'JP', 'Tokyo', ['emitter' => 'warp']);
    });

    $event = $sink->firstOfName(AuthEvent::LOGIN_NEW_LOCATION);

    expect($claimed)->toBeTrue()
        ->and($mailer->sent)->toHaveCount(1)
        ->and($mailer->lastRecipients())->toBe([$user->email])
        ->and($event)->not->toBeNull()
        ->and($event->emitter)->toBe('warp')
        ->and($event->userId)->toBe((int)$user->id)
        ->and($event->details)->toBe(['country' => 'JP', 'city' => 'Tokyo']);
});

it('lets a second consumer claim nothing, so one trip is one email', function() {
    $user = locationsUser();
    $sink = new CollectingAuditSink();
    AuthKit::$plugin->getAudit()->setSinks([$sink]);
    $second = null;

    $mailer = withCollectingMailer(function() use ($user, &$second) {
        $service = new Locations();
        $service->alert($user, 'JP', 'Tokyo', ['emitter' => 'warp']);
        $second = $service->alert($user, 'JP', 'Tokyo', ['emitter' => 'warden']);
    });

    expect($second)->toBeFalse()
        ->and($mailer->sent)->toHaveCount(1)
        ->and($sink->events)->toHaveCount(1);
});

it('alerts again once the dedupe window has passed', function() {
    $user = locationsUser();

    $mailer = withCollectingMailer(function() use ($user) {
        $service = new Locations();
        $service->alert($user, 'JP', 'Tokyo');

        // Backdate the claim past the window: a member who leaves and returns
        // long after should hear about it again, not be silently swallowed.
        Db::update(Table::LOCATIONS, [
            'dateAlerted' => Db::prepareDateForDb(new DateTime("-{$service->alertWindow} seconds -1 minute", new DateTimeZone('UTC'))),
        ], ['userId' => (int)$user->id]);

        $service->alert($user, 'JP', 'Tokyo');
    });

    expect($mailer->sent)->toHaveCount(2);
});

it('records the audit fact but sends nothing when notification is off', function() {
    $user = locationsUser();
    $sink = new CollectingAuditSink();
    AuthKit::$plugin->getAudit()->setSinks([$sink]);

    $mailer = withCollectingMailer(function() use ($user) {
        (new Locations())->alert($user, 'JP', 'Tokyo', ['notify' => false]);
    });

    expect($mailer->sent)->toHaveCount(0)
        ->and($sink->firstOfName(AuthEvent::LOGIN_NEW_LOCATION))->not->toBeNull();
});

it('composes from a consumer supplied message key', function() {
    $user = locationsUser();

    $mailer = withCollectingMailer(function() use ($user) {
        (new Locations())->alert($user, 'JP', 'Tokyo', ['messageKey' => Locations::MESSAGE_KEY_NEW_LOCATION]);
    });

    expect($mailer->sent)->toHaveCount(1)
        ->and($mailer->sent[0]->key)->toBe(Locations::MESSAGE_KEY_NEW_LOCATION);
});

it('claims nothing for an unresolvable location', function() {
    $user = locationsUser();

    $mailer = withCollectingMailer(function() use ($user) {
        expect((new Locations())->alert($user, null, 'Tokyo'))->toBeFalse();
    });

    expect($mailer->sent)->toHaveCount(0);
});

it('names a country-only location without a stray comma', function() {
    $user = locationsUser();

    $mailer = withCollectingMailer(function() use ($user) {
        (new Locations())->alert($user, 'JP', null);
    });

    expect($mailer->sent[0]->variables['location'])->toBe('JP');
});

it('resolves through the module service accessor', function() {
    expect(AuthKit::getInstance()->getLocations())->toBeInstanceOf(Locations::class);
});
