<?php

declare(strict_types=1);

use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Qiick\ApiKeys\Console\Commands\NotifyExpiringApiKeysCommand;
use Qiick\ApiKeys\Contracts\ApiKeyRepository;
use Qiick\ApiKeys\Contracts\Clock;
use Qiick\ApiKeys\Contracts\ExpiryRecipientResolver;
use Qiick\ApiKeys\Contracts\LegacyFormatWarningGate;
use Qiick\ApiKeys\Events\ApiKeyExpiryNoticeSent;
use Qiick\ApiKeys\Events\ApiKeyLegacyFormatWarningSent;
use Qiick\ApiKeys\ExpiryRecipient;
use Qiick\ApiKeys\Laravel\ApiKeysServiceProvider;
use Qiick\ApiKeys\Notifications\ApiKeyExpiringNotification;
use Qiick\ApiKeys\Notifications\ApiKeyLegacyFormatWarningNotification;
use Qiick\ApiKeys\Testing\FakeLegacyFormatWarningGate;
use Qiick\ApiKeys\Testing\FixedClock;
use Qiick\ApiKeys\Testing\InMemoryApiKeyRecord;
use Qiick\ApiKeys\Tests\Support\FailingForKeyExpiryNotification;
use Qiick\ApiKeys\Tests\Support\FailingForKeyLegacyWarningNotification;
use Qiick\ApiKeys\Tests\Support\RecordingRecipientResolver;
use Qiick\ApiKeys\Tests\Support\ScriptedApiKeyRepository;

mutates(NotifyExpiringApiKeysCommand::class);

const COMMAND_NOW = '2026-11-01T00:00:00+00:00';

function commandRecord(string $publicIdSuffix, ?string $expiresAt = '2026-11-05T00:00:00+00:00', int $tokenVersion = 2): InMemoryApiKeyRecord
{
    $record = (new InMemoryApiKeyRecord(
        publicId: '018f0000-0000-7000-8000-0000000000'.$publicIdSuffix,
        keyPrefix: 'tst_test_'.strtoupper(str_pad($publicIdSuffix, 8, 'X')),
        keyHash: 'hash-'.$publicIdSuffix,
        scopes: ['items:read'],
    ))->withTokenVersion($tokenVersion);

    return $expiresAt === null ? $record : $record->withExpiresAt(new DateTimeImmutable($expiresAt));
}

function commandNotifiable(int $key): object
{
    return new class($key)
    {
        use Notifiable;

        public function __construct(private int $key) {}

        public function getKey(): int
        {
            return $this->key;
        }

        public function routeNotificationForMail(): string
        {
            return 'owner'.$this->key.'@example.com';
        }
    };
}

/**
 * Binds the command's collaborators; the legacy warning is off unless a test turns it on.
 */
function bindCommand(ScriptedApiKeyRepository $repository, RecordingRecipientResolver $resolver, LegacyFormatWarningGate $gate = new FakeLegacyFormatWarningGate): void
{
    app()->instance(ApiKeyRepository::class, $repository);
    app()->instance(ExpiryRecipientResolver::class, $resolver);
    app()->instance(LegacyFormatWarningGate::class, $gate);
    app()->instance(Clock::class, new FixedClock(new DateTimeImmutable(COMMAND_NOW)));

    config([
        'api-keys.expiry.notice_days' => 7,
        'api-keys.expiry.claim_lease_seconds' => 900,
        'api-keys.expiry.recipients' => ['owner'],
        'api-keys.expiry.notification' => ApiKeyExpiringNotification::class,
        'api-keys.legacy.accept_until' => null,
        'api-keys.legacy.warn_days_before' => 90,
        'api-keys.legacy.warning_notification' => ApiKeyLegacyFormatWarningNotification::class,
    ]);
}

it('refuses a notice window or a lease that is not a whole number in range', function (string $key, mixed $value, string $message): void {
    bindCommand(new ScriptedApiKeyRepository, new RecordingRecipientResolver);
    config([$key => $value]);

    $this->artisan(NotifyExpiringApiKeysCommand::class)
        ->expectsOutputToContain($message)
        ->assertFailed();
})->with([
    'negative window' => ['api-keys.expiry.notice_days', -1, 'api-keys.expiry.notice_days must be an integer >= 0.'],
    'window typo' => ['api-keys.expiry.notice_days', 'seven', 'api-keys.expiry.notice_days must be an integer >= 0.'],
    'zero lease' => ['api-keys.expiry.claim_lease_seconds', 0, 'api-keys.expiry.claim_lease_seconds must be an integer >= 1.'],
    'lease typo' => ['api-keys.expiry.claim_lease_seconds', '15min', 'api-keys.expiry.claim_lease_seconds must be an integer >= 1.'],
]);

it('refuses an expiry notification that is not a class', function (mixed $notification): void {
    bindCommand(new ScriptedApiKeyRepository, new RecordingRecipientResolver);
    config(['api-keys.expiry.notification' => $notification]);

    $this->artisan(NotifyExpiringApiKeysCommand::class)
        ->expectsOutputToContain('api-keys.expiry.notification must be a notification class.')
        ->assertFailed();
})->with(['missing class' => ['App\\Notifications\\Missing'], 'not a string' => [42]]);

it('accepts the smallest window and lease, and looks ahead exactly notice_days', function (): void {
    Notification::fake();
    $repository = new ScriptedApiKeyRepository([commandRecord('a1')]);
    bindCommand($repository, new RecordingRecipientResolver([commandRecord('a1')->publicId() => [commandNotifiable(1)]]));
    config(['api-keys.expiry.notice_days' => 0, 'api-keys.expiry.claim_lease_seconds' => 1]);

    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();

    expect($repository->expiringUntil?->format(DateTimeInterface::ATOM))->toBe(COMMAND_NOW)
        ->and($repository->claimLeaseSeconds)->toBe([1]);

    config(['api-keys.expiry.notice_days' => 7, 'api-keys.expiry.claim_lease_seconds' => 900]);
    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();

    expect($repository->expiringUntil?->format(DateTimeInterface::ATOM))->toBe('2026-11-08T00:00:00+00:00')
        ->and($repository->claimLeaseSeconds)->toBe([1, 900]);
});

it('notifies every eligible key, skipping the others without stopping the run', function (): void {
    Notification::fake();
    Event::fake([ApiKeyExpiryNoticeSent::class]);
    $first = commandNotifiable(1);
    $second = commandNotifiable(2);
    $records = [
        commandRecord('b0', expiresAt: null),   // a product query may return it: skipped
        commandRecord('b1'),                     // no recipient yet: skipped, not claimed
        commandRecord('b2'),                     // another worker holds the claim
        commandRecord('b3'),
        commandRecord('f0'),                     // delivery fails: released, reported
        commandRecord('b4'),
    ];
    $repository = new ScriptedApiKeyRepository($records, lostClaimPublicIds: [$records[2]->publicId()]);
    bindCommand($repository, new RecordingRecipientResolver([
        $records[2]->publicId() => [$first],
        $records[3]->publicId() => [$first],
        $records[4]->publicId() => [$first],
        $records[5]->publicId() => [$second],
    ]));
    config(['api-keys.expiry.notification' => FailingForKeyExpiryNotification::class]);

    $this->artisan(NotifyExpiringApiKeysCommand::class)
        ->expectsOutputToContain('Expiry notice failed for '.FailingForKeyExpiryNotification::FAILING_PUBLIC_ID.': mail transport down')
        ->expectsOutputToContain('Expiry notices sent: 2')
        ->expectsOutputToContain('Legacy-format warnings sent: 0')
        ->assertSuccessful();

    expect($repository->claimedPublicIds)->toBe([$records[3]->publicId(), $records[4]->publicId(), $records[5]->publicId()])
        ->and($repository->releasedPublicIds)->toBe([$records[4]->publicId()])
        ->and($repository->markedPublicIds)->toBe([$records[3]->publicId(), $records[5]->publicId()]);
    Notification::assertSentTo($first, FailingForKeyExpiryNotification::class);
    Notification::assertSentTo($second, FailingForKeyExpiryNotification::class);
    Event::assertDispatchedTimes(ApiKeyExpiryNoticeSent::class, 2);
});

it('asks the resolver for the configured roles, ignoring unknown and non-string entries', function (mixed $configured, array $expectedRoles): void {
    $resolver = new RecordingRecipientResolver;
    bindCommand(new ScriptedApiKeyRepository([commandRecord('c1')]), $resolver);
    config(['api-keys.expiry.recipients' => $configured]);

    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();

    expect($resolver->requestedRoles)->toBe([$expectedRoles]);
})->with([
    'listed roles' => [['organisation', 5, 'bogus', 'owner'], [ExpiryRecipient::Organisation, ExpiryRecipient::Owner]],
    'not a list' => ['owner', [ExpiryRecipient::Owner, ExpiryRecipient::Issuer]],
]);

/**
 * Turns the legacy warning on with a cut-off on 2026-12-01 and a 30-day window.
 */
function enableLegacyWarning(string $acceptUntil = '2026-12-01T00:00:00Z'): void
{
    config([
        'api-keys.legacy.accept_until' => $acceptUntil,
        'api-keys.legacy.warn_days_before' => 30,
    ]);
}

it('warns every active legacy key inside the window, skipping the others without stopping the run', function (): void {
    Notification::fake();
    Event::fake([ApiKeyLegacyFormatWarningSent::class]);
    $first = commandNotifiable(1);
    $legacy = [
        commandRecord('d1', tokenVersion: 0),     // no recipient: skipped
        commandRecord('d2', tokenVersion: 0),     // already warned: skipped
        commandRecord('d3', tokenVersion: 0),
        commandRecord('f0', tokenVersion: 0),     // delivery fails: released, reported
        commandRecord('d4', tokenVersion: 0),
    ];
    $gate = new FakeLegacyFormatWarningGate;
    $gate->sentKeys['api-keys:legacy-format-warning:'.$legacy[1]->publicId().':2026-12-01T00:00:00+00:00'] = true;
    $recipients = array_fill_keys(array_map(fn ($record) => $record->publicId(), array_slice($legacy, 1)), [$first]);
    bindCommand(new ScriptedApiKeyRepository(activeLegacy: $legacy), new RecordingRecipientResolver($recipients), $gate);
    enableLegacyWarning();
    config(['api-keys.legacy.warning_notification' => FailingForKeyLegacyWarningNotification::class]);

    $this->artisan(NotifyExpiringApiKeysCommand::class)
        ->expectsOutputToContain('Legacy-format warning failed for '.FailingForKeyLegacyWarningNotification::FAILING_PUBLIC_ID.': mail transport down')
        ->expectsOutputToContain('Legacy-format warnings sent: 2')
        ->assertSuccessful();

    expect(array_keys($gate->sentKeys))->toBe([
        'api-keys:legacy-format-warning:'.$legacy[1]->publicId().':2026-12-01T00:00:00+00:00',
        'api-keys:legacy-format-warning:'.$legacy[2]->publicId().':2026-12-01T00:00:00+00:00',
        'api-keys:legacy-format-warning:'.$legacy[4]->publicId().':2026-12-01T00:00:00+00:00',
    ])
        ->and($gate->leaseOwnersByKey)->toBe([]);
    Event::assertDispatchedTimes(ApiKeyLegacyFormatWarningSent::class, 2);
});

it('warns from the first second of the window until just before the cut-off', function (string $now, int $expectedWarnings): void {
    Notification::fake();
    $legacy = commandRecord('e1', tokenVersion: 0);
    bindCommand(new ScriptedApiKeyRepository(activeLegacy: [$legacy]), new RecordingRecipientResolver([$legacy->publicId() => [commandNotifiable(1)]]));
    enableLegacyWarning();
    app()->instance(Clock::class, new FixedClock(new DateTimeImmutable($now)));

    $this->artisan(NotifyExpiringApiKeysCommand::class)
        ->expectsOutputToContain("Legacy-format warnings sent: {$expectedWarnings}")
        ->assertSuccessful();
})->with([
    'a second before the window' => ['2026-10-31T23:59:59+00:00', 0],
    'the first second of the window' => ['2026-11-01T00:00:00+00:00', 1],
    'the last second' => ['2026-11-30T23:59:59+00:00', 1],
    'at the cut-off' => ['2026-12-01T00:00:00+00:00', 0],
]);

it('sends no legacy warning when the window is zero days', function (): void {
    Notification::fake();
    $legacy = commandRecord('e2', tokenVersion: 0);
    bindCommand(new ScriptedApiKeyRepository(activeLegacy: [$legacy]), new RecordingRecipientResolver([$legacy->publicId() => [commandNotifiable(1)]]));
    enableLegacyWarning();
    config(['api-keys.legacy.warn_days_before' => '0']);

    $this->artisan(NotifyExpiringApiKeysCommand::class)
        ->expectsOutputToContain('Legacy-format warnings sent: 0')
        ->assertSuccessful();
});

it('refuses a warning window changed after boot to something other than a whole number', function (mixed $warnDays): void {
    $legacy = commandRecord('e4', tokenVersion: 0);
    bindCommand(new ScriptedApiKeyRepository(activeLegacy: [$legacy]), new RecordingRecipientResolver([$legacy->publicId() => [commandNotifiable(1)]]));
    enableLegacyWarning();
    config(['api-keys.legacy.warn_days_before' => $warnDays]);

    expect(fn () => $this->artisan(NotifyExpiringApiKeysCommand::class)->run())
        ->toThrow(InvalidArgumentException::class, 'api-keys.legacy.warn_days_before must be a whole number >= 0.');
})->with(['negative' => [-1], 'typo' => ['ninety']]);

it('reports a legacy warning notification that is not a class, after sending the expiry notices', function (mixed $notification): void {
    Notification::fake();
    $legacy = commandRecord('e3', tokenVersion: 0);
    bindCommand(new ScriptedApiKeyRepository(activeLegacy: [$legacy]), new RecordingRecipientResolver([$legacy->publicId() => [commandNotifiable(1)]]));
    enableLegacyWarning();
    config(['api-keys.legacy.warning_notification' => $notification]);

    $this->artisan(NotifyExpiringApiKeysCommand::class)
        ->expectsOutputToContain('api-keys.legacy.warning_notification must be a notification class.')
        ->doesntExpectOutputToContain('Legacy-format warning failed')
        ->expectsOutputToContain('Legacy-format warnings sent: 0')
        ->assertSuccessful();
})->with(['missing class' => ['App\\Notifications\\Missing'], 'not a string' => [42]]);

it('notifies every recipient a resolver yields, even under repeated keys', function (): void {
    Notification::fake();
    $first = commandNotifiable(1);
    $second = commandNotifiable(2);
    $expiring = commandRecord('g1');
    $legacy = commandRecord('g2', tokenVersion: 0);
    bindCommand(
        new ScriptedApiKeyRepository([$expiring], [$legacy]),
        new RecordingRecipientResolver([$expiring->publicId() => [$first, $second], $legacy->publicId() => [$first, $second]], isYieldedOneByOne: true),
    );
    enableLegacyWarning();

    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();

    Notification::assertSentTo($second, ApiKeyExpiringNotification::class);
    Notification::assertSentTo($first, ApiKeyExpiringNotification::class);
    Notification::assertSentTo($second, ApiKeyLegacyFormatWarningNotification::class);
    Notification::assertSentTo($first, ApiKeyLegacyFormatWarningNotification::class);
});

it('warns with a one-day window from exactly one day before the cut-off', function (string $now, int $expectedWarnings): void {
    Notification::fake();
    $legacy = commandRecord('g3', tokenVersion: 0);
    bindCommand(new ScriptedApiKeyRepository(activeLegacy: [$legacy]), new RecordingRecipientResolver([$legacy->publicId() => [commandNotifiable(1)]]));
    enableLegacyWarning();
    config(['api-keys.legacy.warn_days_before' => '1']);
    app()->instance(Clock::class, new FixedClock(new DateTimeImmutable($now)));

    $this->artisan(NotifyExpiringApiKeysCommand::class)
        ->expectsOutputToContain("Legacy-format warnings sent: {$expectedWarnings}")
        ->assertSuccessful();
})->with([
    'a second before' => ['2026-11-29T23:59:59+00:00', 0],
    'one day before' => ['2026-11-30T00:00:00+00:00', 1],
]);

it('runs on a config published before the nested expiry and legacy keys existed', function (): void {
    Notification::fake();
    $record = commandRecord('h1');
    bindCommand(new ScriptedApiKeyRepository([$record]), new RecordingRecipientResolver([$record->publicId() => [commandNotifiable(1)]]));
    config(['api-keys.expiry' => ['notice_days' => 7], 'api-keys.legacy' => []]);
    app()->getProvider(ApiKeysServiceProvider::class)->register();

    $this->artisan(NotifyExpiringApiKeysCommand::class)
        ->expectsOutputToContain('Expiry notices sent: 1')
        ->assertSuccessful();
});
