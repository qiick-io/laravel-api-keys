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
use Qiick\ApiKeys\Contracts\RandomSource;
use Qiick\ApiKeys\Events\ApiKeyExpiryNoticeSent;
use Qiick\ApiKeys\Notifications\ApiKeyExpiringNotification;
use Qiick\ApiKeys\Testing\FakeApiKeyRepository;
use Qiick\ApiKeys\Testing\FakeExpiryRecipientResolver;
use Qiick\ApiKeys\Testing\FakeLegacyFormatWarningGate;
use Qiick\ApiKeys\Testing\FixedClock;
use Qiick\ApiKeys\Testing\FixedRandomSource;
use Qiick\ApiKeys\Testing\InMemoryApiKeyRecord;
use Qiick\ApiKeys\Tests\Support\ThrowingExpiryNotification;

mutates(NotifyExpiringApiKeysCommand::class);

/**
 * B1: expiry notice claim lease + mark-after-send are load-bearing.
 */
function expiryNoticeNotifiable(): object
{
    return new class
    {
        use Notifiable;

        public function getKey(): int
        {
            return 1;
        }

        public function routeNotificationForMail(): string
        {
            return 'owner@example.com';
        }
    };
}

/**
 * @return array{0: FakeApiKeyRepository, 1: object}
 */
function bindExpiryNoticeCommand(InMemoryApiKeyRecord $record, DateTimeImmutable $now): array
{
    $notifiable = expiryNoticeNotifiable();
    $repository = new FakeApiKeyRepository([$record], $now);
    $resolver = new FakeExpiryRecipientResolver([$notifiable]);

    app()->instance(FakeApiKeyRepository::class, $repository);
    app()->instance(ApiKeyRepository::class, $repository);
    app()->instance(ExpiryRecipientResolver::class, $resolver);
    app()->instance(LegacyFormatWarningGate::class, new FakeLegacyFormatWarningGate);
    app()->instance(Clock::class, new FixedClock($now));

    config([
        'api-keys.expiry.notice_days' => 7,
        'api-keys.expiry.claim_lease_seconds' => 900,
        'api-keys.expiry.recipients' => ['owner'],
        'api-keys.expiry.notification' => ApiKeyExpiringNotification::class,
        'api-keys.legacy.accept_until' => null,
        'api-keys.legacy.warn_days_before' => 0,
    ]);

    return [$repository, $notifiable];
}

it('B1: a second run sends nothing after markExpiryNotified', function (): void {
    Notification::fake();
    Event::fake([ApiKeyExpiryNoticeSent::class]);

    $now = new DateTimeImmutable('2026-01-10T12:00:00+00:00');
    $record = (new InMemoryApiKeyRecord(
        publicId: '018f0000-0000-7000-8000-0000000000e1',
        keyPrefix: 'tst_test_expiry01',
        keyHash: 'hash',
        scopes: ['items:read'],
    ))->withExpiresAt(new DateTimeImmutable('2026-01-15T00:00:00+00:00'));

    [$repository, $notifiable] = bindExpiryNoticeCommand($record, $now);

    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();

    Notification::assertSentTo($notifiable, ApiKeyExpiringNotification::class);
    Event::assertDispatched(ApiKeyExpiryNoticeSent::class);
    expect($repository->expiryNotifications)->toHaveCount(1)
        ->and($repository->findByPublicId($record->publicId())?->expiryNotifiedAt())->not->toBeNull()
        ->and($repository->findByPublicId($record->publicId())?->expiryNoticeClaimedAt())->toBeNull();

    Notification::fake();
    Event::fake([ApiKeyExpiryNoticeSent::class]);

    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();

    Notification::assertNothingSent();
    Event::assertNotDispatched(ApiKeyExpiryNoticeSent::class);
    expect($repository->expiryNotifications)->toHaveCount(1);
});

it('B1: a missed day still sends when expiry_notified_at was never stamped', function (): void {
    Notification::fake();

    $dayTwo = new DateTimeImmutable('2026-01-11T12:00:00+00:00');
    $record = (new InMemoryApiKeyRecord(
        publicId: '018f0000-0000-7000-8000-0000000000e2',
        keyPrefix: 'tst_test_expiry02',
        keyHash: 'hash',
        scopes: ['items:read'],
    ))->withExpiresAt(new DateTimeImmutable('2026-01-16T00:00:00+00:00'));

    // Day one was skipped (no stamp). Day two must still notify.
    [$repository, $notifiable] = bindExpiryNoticeCommand($record, $dayTwo);

    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();

    Notification::assertSentTo($notifiable, ApiKeyExpiringNotification::class);
    expect($repository->expiryNotifications)->toHaveCount(1);
});

it('B1: send failure does not stamp and the next successful run retries', function (): void {
    Event::fake([ApiKeyExpiryNoticeSent::class]);

    $now = new DateTimeImmutable('2026-01-10T12:00:00+00:00');
    $record = (new InMemoryApiKeyRecord(
        publicId: '018f0000-0000-7000-8000-0000000000e3',
        keyPrefix: 'tst_test_expiry03',
        keyHash: 'hash',
        scopes: ['items:read'],
    ))->withExpiresAt(new DateTimeImmutable('2026-01-15T00:00:00+00:00'));

    [$repository, $notifiable] = bindExpiryNoticeCommand($record, $now);
    config(['api-keys.expiry.notification' => ThrowingExpiryNotification::class]);

    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();

    expect($repository->expiryNotifications)->toBe([])
        ->and($repository->findByPublicId($record->publicId())?->expiryNotifiedAt())->toBeNull()
        ->and($repository->findByPublicId($record->publicId())?->expiryNoticeClaimedAt())->toBeNull();
    Event::assertNotDispatched(ApiKeyExpiryNoticeSent::class);

    Notification::fake();
    Event::fake([ApiKeyExpiryNoticeSent::class]);
    config(['api-keys.expiry.notification' => ApiKeyExpiringNotification::class]);

    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();

    Notification::assertSentTo($notifiable, ApiKeyExpiringNotification::class);
    expect($repository->expiryNotifications)->toHaveCount(1);
    Event::assertDispatched(ApiKeyExpiryNoticeSent::class);
});

it('B1: a successful send keeps the notified stamp and dispatches the event', function (): void {
    Notification::fake();
    Event::fake([ApiKeyExpiryNoticeSent::class]);

    $now = new DateTimeImmutable('2026-01-10T12:00:00+00:00');
    $record = (new InMemoryApiKeyRecord(
        publicId: '018f0000-0000-7000-8000-0000000000e4',
        keyPrefix: 'tst_test_expiry04',
        keyHash: 'hash',
        scopes: ['items:read'],
    ))->withExpiresAt(new DateTimeImmutable('2026-01-15T00:00:00+00:00'));

    [$repository, $notifiable] = bindExpiryNoticeCommand($record, $now);

    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();

    Notification::assertSentTo($notifiable, ApiKeyExpiringNotification::class);
    expect($repository->expiryNotifications)->toHaveCount(1)
        ->and($repository->expiryNotifications[0]['notifiedAt']->format(DateTimeInterface::ATOM))
        ->toBe($now->format(DateTimeInterface::ATOM));
    Event::assertDispatched(ApiKeyExpiryNoticeSent::class, function (ApiKeyExpiryNoticeSent $event) use ($record, $now): bool {
        return $event->apiKeyId === $record->publicId()
            && $event->notifiedAt == $now;
    });
});

it('B1: concurrent claimExpiryNotice allows only one winner within the lease', function (): void {
    Notification::fake();
    Event::fake([ApiKeyExpiryNoticeSent::class]);

    $now = new DateTimeImmutable('2026-01-10T12:00:00+00:00');
    $record = (new InMemoryApiKeyRecord(
        publicId: '018f0000-0000-7000-8000-0000000000e5',
        keyPrefix: 'tst_test_expiry05',
        keyHash: 'hash',
        scopes: ['items:read'],
    ))->withExpiresAt(new DateTimeImmutable('2026-01-15T00:00:00+00:00'));

    [$repository, $notifiable] = bindExpiryNoticeCommand($record, $now);

    expect($repository->claimExpiryNotice($record, $now, 900, 'token-a'))->toBeTrue()
        ->and($repository->claimExpiryNotice($record, $now, 900, 'token-b'))->toBeFalse()
        ->and($repository->findByPublicId($record->publicId())?->expiryNoticeClaimedAt())->not->toBeNull()
        ->and($repository->findByPublicId($record->publicId())?->expiryNotifiedAt())->toBeNull();

    // Second artisan pass must not send again while the lease is held.
    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();

    Notification::assertNothingSent();
    Event::assertNotDispatched(ApiKeyExpiryNoticeSent::class);
});

it('B1: crash after claim is reclaimable once the lease expires', function (): void {
    Notification::fake();
    Event::fake([ApiKeyExpiryNoticeSent::class]);

    $claimAt = new DateTimeImmutable('2026-01-10T12:00:00+00:00');
    $record = (new InMemoryApiKeyRecord(
        publicId: '018f0000-0000-7000-8000-0000000000e6',
        keyPrefix: 'tst_test_expiry06',
        keyHash: 'hash',
        scopes: ['items:read'],
    ))->withExpiresAt(new DateTimeImmutable('2026-01-15T00:00:00+00:00'));

    [$repository, $notifiable] = bindExpiryNoticeCommand($record, $claimAt);
    config(['api-keys.expiry.claim_lease_seconds' => 60]);

    // Worker A claims, then dies before send (no release, no mark).
    expect($repository->claimExpiryNotice($record, $claimAt, 60, 'token-a'))->toBeTrue()
        ->and($repository->findByPublicId($record->publicId())?->expiryNoticeClaimedAt())->not->toBeNull()
        ->and($repository->findByPublicId($record->publicId())?->expiryNotifiedAt())->toBeNull();

    // Still inside the lease: artisan must not send.
    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();
    Notification::assertNothingSent();
    Event::assertNotDispatched(ApiKeyExpiryNoticeSent::class);

    // After the lease: reclaim and send.
    $afterLease = $claimAt->modify('+61 seconds');
    app()->instance(Clock::class, new FixedClock($afterLease));
    $repository = $repository->withNow($afterLease);
    app()->instance(FakeApiKeyRepository::class, $repository);
    app()->instance(ApiKeyRepository::class, $repository);

    Notification::fake();
    Event::fake([ApiKeyExpiryNoticeSent::class]);

    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();

    Notification::assertSentTo($notifiable, ApiKeyExpiringNotification::class);
    Event::assertDispatched(ApiKeyExpiryNoticeSent::class);
    expect($repository->expiryNotifications)->toHaveCount(1)
        ->and($repository->findByPublicId($record->publicId())?->expiryNotifiedAt())->not->toBeNull()
        ->and($repository->findByPublicId($record->publicId())?->expiryNoticeClaimedAt())->toBeNull();
});

it('N1: Fake claim CAS rejects a stale observed version', function (): void {
    $now = new DateTimeImmutable('2026-01-10T12:00:00+00:00');
    $record = (new InMemoryApiKeyRecord(
        publicId: '018f0000-0000-7000-8000-0000000000e7',
        keyPrefix: 'tst_test_expiry07',
        keyHash: 'hash',
        scopes: ['items:read'],
    ))->withExpiresAt(new DateTimeImmutable('2026-01-15T00:00:00+00:00'));

    $repository = new FakeApiKeyRepository([$record], $now);
    $staleVersion = $repository->casVersionFor($record->publicId());

    expect($repository->claimExpiryNotice($record, $now, 900, 'token-a'))->toBeTrue()
        ->and($repository->casVersionFor($record->publicId()))->toBe($staleVersion + 1)
        ->and($repository->claimExpiryNoticeWithObservedVersion($record, $now, 900, $staleVersion, 'token-b'))
        ->toBeFalse();
});

function expiringRecord(string $suffix): InMemoryApiKeyRecord
{
    return (new InMemoryApiKeyRecord(
        publicId: '018f0000-0000-7000-8000-0000000001'.$suffix,
        keyPrefix: 'tst_test_expiry'.$suffix,
        keyHash: 'hash',
        scopes: ['items:read'],
    ))->withExpiresAt(new DateTimeImmutable('2026-01-15T00:00:00+00:00'));
}

it('lets only the claim\'s own token mark or release it, so a run whose lease expired cannot touch the next run\'s claim', function (): void {
    $now = new DateTimeImmutable('2026-01-10T12:00:00+00:00');
    $record = expiringRecord('a1');
    $repository = new FakeApiKeyRepository([$record], $now);

    expect($repository->claimExpiryNotice($record, $now, 60, 'token-a'))->toBeTrue();

    $afterLease = $now->modify('+61 seconds');

    expect($repository->claimExpiryNotice($record, $afterLease, 60, 'token-b'))->toBeTrue()
        ->and($repository->markExpiryNotified($record, $afterLease, 'token-a'))->toBeFalse();

    $repository->releaseExpiryNotice($record, 'token-a');

    expect($repository->findByPublicId($record->publicId())?->expiryNoticeClaimedAt())->toEqual($afterLease)
        ->and($repository->findByPublicId($record->publicId())?->expiryNotifiedAt())->toBeNull()
        ->and($repository->markExpiryNotified($record, $afterLease, 'token-b'))->toBeTrue()
        ->and($repository->findByPublicId($record->publicId())?->expiryNotifiedAt())->toEqual($afterLease)
        ->and($repository->expiryNotifications)->toHaveCount(1);
});

it('releases a claim only with its own token', function (): void {
    $now = new DateTimeImmutable('2026-01-10T12:00:00+00:00');
    $record = expiringRecord('a2');
    $repository = new FakeApiKeyRepository([$record], $now);

    $repository->claimExpiryNotice($record, $now, 900, 'token-a');
    $repository->releaseExpiryNotice($record, 'token-b');

    expect($repository->claimExpiryNotice($record, $now, 900, 'token-c'))->toBeFalse();

    $repository->releaseExpiryNotice($record, 'token-a');

    expect($repository->findByPublicId($record->publicId())?->expiryNoticeClaimedAt())->toBeNull()
        ->and($repository->claimExpiryNotice($record, $now, 900, 'token-c'))->toBeTrue();
});

it('binds the claim and the mark to the expiry that was selected', function (): void {
    $now = new DateTimeImmutable('2026-01-10T12:00:00+00:00');
    $selected = expiringRecord('a3');
    $rotated = $selected->withExpiresAt(new DateTimeImmutable('2026-04-15T00:00:00+00:00'));
    $repository = new FakeApiKeyRepository([$selected], $now);

    expect($repository->claimExpiryNotice($selected, $now, 900, 'token-a'))->toBeTrue();

    // The key is rotated to a new expiry while the notice for the old one is in flight.
    $repository->setRecords([$rotated->withExpiryNoticeClaimedAt($now)]);

    expect($repository->markExpiryNotified($selected, $now, 'token-a'))->toBeFalse()
        ->and($repository->findByPublicId($selected->publicId())?->expiryNotifiedAt())->toBeNull()
        ->and($repository->expiryNotifications)->toBe([]);

    // A claim for the old expiry, from a stale select, loses too.
    $fresh = new FakeApiKeyRepository([$rotated], $now);

    expect($fresh->claimExpiryNotice($selected, $now, 900, 'token-b'))->toBeFalse();
});

it('claims with a token from the RandomSource', function (): void {
    Notification::fake();
    $now = new DateTimeImmutable('2026-01-10T12:00:00+00:00');
    [$repository] = bindExpiryNoticeCommand(expiringRecord('a4'), $now);
    app()->instance(RandomSource::class, new FixedRandomSource('claim-token-seed-0123456789abcdef'));

    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();

    expect($repository->claimTokensUsed)->toBe([bin2hex(substr('claim-token-seed-0123456789abcdef', 0, 16))]);
});

it('matches the selected expiry within the second, as the SQL does', function (): void {
    $now = new DateTimeImmutable('2026-01-10T12:00:00+00:00');
    $stored = expiringRecord('a5')->withExpiresAt(new DateTimeImmutable('2026-01-15T00:00:00.400000+00:00'));
    $selected = $stored->withExpiresAt(new DateTimeImmutable('2026-01-15T00:00:00+00:00'));
    $repository = new FakeApiKeyRepository([$stored], $now);

    expect($repository->claimExpiryNotice($selected, $now, 900, 'token-a'))->toBeTrue()
        ->and($repository->markExpiryNotified($selected, $now, 'token-a'))->toBeTrue();
});

