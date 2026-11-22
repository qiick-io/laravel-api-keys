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
use Qiick\ApiKeys\Notifications\ApiKeyExpiringNotification;
use Qiick\ApiKeys\Testing\FakeApiKeyRepository;
use Qiick\ApiKeys\Testing\FakeExpiryRecipientResolver;
use Qiick\ApiKeys\Testing\FakeLegacyFormatWarningGate;
use Qiick\ApiKeys\Testing\FixedClock;
use Qiick\ApiKeys\Testing\InMemoryApiKeyRecord;
use Qiick\ApiKeys\Tests\Support\ThrowingExpiryNotification;

/**
 * B1: markExpiryNotified is load-bearing on the command path.
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
        ->and($repository->findByPublicId($record->publicId())?->expiryNotifiedAt())->not->toBeNull();

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
        ->and($repository->findByPublicId($record->publicId())?->expiryNotifiedAt())->toBeNull();
    Event::assertNotDispatched(ApiKeyExpiryNoticeSent::class);

    Notification::fake();
    Event::fake([ApiKeyExpiryNoticeSent::class]);
    config(['api-keys.expiry.notification' => ApiKeyExpiringNotification::class]);

    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();

    Notification::assertSentTo($notifiable, ApiKeyExpiringNotification::class);
    expect($repository->expiryNotifications)->toHaveCount(1);
    Event::assertDispatched(ApiKeyExpiryNoticeSent::class);
});

it('B1: the stamp happens only after a successful send', function (): void {
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
