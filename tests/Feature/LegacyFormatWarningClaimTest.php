<?php

declare(strict_types=1);

use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Qiick\ApiKeys\CacheLegacyFormatWarningGate;
use Qiick\ApiKeys\Console\Commands\NotifyExpiringApiKeysCommand;
use Qiick\ApiKeys\Contracts\ApiKeyRepository;
use Qiick\ApiKeys\Contracts\Clock;
use Qiick\ApiKeys\Contracts\ExpiryRecipientResolver;
use Qiick\ApiKeys\Contracts\LegacyFormatWarningGate;
use Qiick\ApiKeys\Events\ApiKeyLegacyFormatWarningSentEvent;
use Qiick\ApiKeys\Notifications\ApiKeyLegacyFormatWarningNotification;
use Qiick\ApiKeys\Testing\FakeApiKeyRepository;
use Qiick\ApiKeys\Testing\FakeExpiryRecipientResolver;
use Qiick\ApiKeys\Testing\FixedClock;
use Qiick\ApiKeys\Testing\InMemoryApiKeyRecord;
use Qiick\ApiKeys\Tests\Support\ThrowingLegacyFormatWarningNotification;

mutates(CacheLegacyFormatWarningGate::class);

/**
 * The legacy-format warning must follow the expiry-notice protocol: resolve
 * recipients, take a lease, send, then mark sent. A missing recipient or a
 * failed send must leave the warning claimable for the next run.
 */
const LEGACY_WARNING_PUBLIC_ID = '018f0000-0000-7000-8000-0000000000d1';

const LEGACY_WARNING_ACCEPT_UNTIL = '2026-12-01T00:00:00+00:00';

function legacyWarningNotifiable(): object
{
    return new class
    {
        use Notifiable;

        public function getKey(): int
        {
            return 7;
        }

        public function routeNotificationForMail(): string
        {
            return 'owner@example.com';
        }
    };
}

function legacyWarningIdempotencyKey(): string
{
    return 'api-keys:legacy-format-warning:'.LEGACY_WARNING_PUBLIC_ID.':'.LEGACY_WARNING_ACCEPT_UNTIL;
}

/**
 * Binds one active token_version 0 key, inside the T−90 window, with the
 * package's default cache-backed warning gate.
 *
 * @param  list<object>  $recipients
 */
function bindLegacyWarningCommand(array $recipients): void
{
    $now = new DateTimeImmutable('2026-11-01T00:00:00+00:00');
    $legacy = (new InMemoryApiKeyRecord(
        publicId: LEGACY_WARNING_PUBLIC_ID,
        keyPrefix: 'ek_ABCDEFGHI',
        keyHash: 'hash',
        scopes: ['items:read'],
    ))->withTokenVersion(0);
    $repository = new FakeApiKeyRepository([$legacy], $now);

    app()->instance(ApiKeyRepository::class, $repository);
    app()->instance(ExpiryRecipientResolver::class, new FakeExpiryRecipientResolver($recipients));
    app()->instance(Clock::class, new FixedClock($now));

    config([
        'api-keys.legacy.accept_until' => LEGACY_WARNING_ACCEPT_UNTIL,
        'api-keys.legacy.warn_days_before' => 90,
        'api-keys.legacy.warning_notification' => ApiKeyLegacyFormatWarningNotification::class,
        'api-keys.expiry.notice_days' => 7,
        'api-keys.expiry.claim_lease_seconds' => 900,
        'api-keys.expiry.recipients' => ['owner'],
    ]);
}

it('does not consume the warning when no recipient resolves yet', function (): void {
    Notification::fake();
    $notifiable = legacyWarningNotifiable();

    bindLegacyWarningCommand([]);
    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();
    Notification::assertNothingSent();

    bindLegacyWarningCommand([$notifiable]);
    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();

    Notification::assertSentToTimes($notifiable, ApiKeyLegacyFormatWarningNotification::class, 1);
});

it('releases the claim when the send fails, so the next run retries', function (): void {
    $notifiable = legacyWarningNotifiable();
    bindLegacyWarningCommand([$notifiable]);
    Event::fake([ApiKeyLegacyFormatWarningSentEvent::class]);
    config(['api-keys.legacy.warning_notification' => ThrowingLegacyFormatWarningNotification::class]);

    $this->artisan(NotifyExpiringApiKeysCommand::class)
        ->expectsOutputToContain('Legacy-format warning failed for '.LEGACY_WARNING_PUBLIC_ID)
        ->assertSuccessful();
    Event::assertNotDispatched(ApiKeyLegacyFormatWarningSentEvent::class);

    Notification::fake();
    config(['api-keys.legacy.warning_notification' => ApiKeyLegacyFormatWarningNotification::class]);
    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();

    Notification::assertSentToTimes($notifiable, ApiKeyLegacyFormatWarningNotification::class, 1);
    Event::assertDispatched(ApiKeyLegacyFormatWarningSentEvent::class);
});

it('lets the warning be reclaimed once a dead worker\'s lease has expired', function (): void {
    Notification::fake();
    $notifiable = legacyWarningNotifiable();
    bindLegacyWarningCommand([$notifiable]);

    // A worker claimed the warning and died before sending or marking it.
    expect(app(LegacyFormatWarningGate::class)->claim(legacyWarningIdempotencyKey(), 900))->toBeString();

    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();
    Notification::assertNothingSent();

    $this->travel(901)->seconds();
    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();

    Notification::assertSentToTimes($notifiable, ApiKeyLegacyFormatWarningNotification::class, 1);
});

it('never re-sends a warning that was sent, even after the lease would have expired', function (): void {
    Notification::fake();
    $notifiable = legacyWarningNotifiable();
    bindLegacyWarningCommand([$notifiable]);

    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();
    $this->travel(30)->days();
    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();

    Notification::assertSentToTimes($notifiable, ApiKeyLegacyFormatWarningNotification::class, 1);
});

it('lets only the lease owner release it, so a late worker cannot free another worker\'s lease', function (): void {
    $gate = app(LegacyFormatWarningGate::class);
    $key = legacyWarningIdempotencyKey();

    $lateWorker = $gate->claim($key, 900);
    $this->travel(901)->seconds();
    $currentWorker = $gate->claim($key, 900);

    expect($lateWorker)->toBeString()
        ->and($currentWorker)->toBeString()
        ->and($currentWorker)->not->toBe($lateWorker);

    $gate->release($key, $lateWorker);

    expect($gate->claim($key, 900))->toBeNull();

    $gate->release($key, $currentWorker);

    expect($gate->claim($key, 900))->toBeString();
});

it('never grants a lease on a warning that was marked sent', function (): void {
    $gate = app(LegacyFormatWarningGate::class);
    $key = legacyWarningIdempotencyKey();

    $owner = $gate->claim($key, 900);
    $gate->markSent($key, $owner);
    $this->travel(901)->seconds();

    expect($gate->claim($key, 900))->toBeNull();
});

it('holds the lease as a cache lock named after the warning, freed once sent or found sent', function (): void {
    $gate = app(LegacyFormatWarningGate::class);
    $key = legacyWarningIdempotencyKey();
    $lease = fn () => Cache::lock($key.':lease', 900);

    $owner = $gate->claim($key, 900);
    expect($lease()->get())->toBeFalse();

    $gate->markSent($key, $owner);
    $probe = $lease();
    expect($probe->get())->toBeTrue();
    $probe->release();

    // A claim on a sent warning takes the lease, sees the marker, and gives the lease back.
    expect($gate->claim($key, 900))->toBeNull()
        ->and($lease()->get())->toBeTrue();
});
