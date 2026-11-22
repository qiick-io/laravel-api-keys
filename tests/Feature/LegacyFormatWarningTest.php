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
use Qiick\ApiKeys\Events\ApiKeyLegacyFormatWarningSent;
use Qiick\ApiKeys\Notifications\ApiKeyLegacyFormatWarningNotification;
use Qiick\ApiKeys\Testing\FakeApiKeyRepository;
use Qiick\ApiKeys\Testing\FakeExpiryRecipientResolver;
use Qiick\ApiKeys\Testing\FakeLegacyFormatWarningGate;
use Qiick\ApiKeys\Testing\FixedClock;
use Qiick\ApiKeys\Testing\InMemoryApiKeyRecord;

it('N2: warns active token_version 0 keys within warn_days_before accept_until, once', function (): void {
    Notification::fake();
    Event::fake([ApiKeyLegacyFormatWarningSent::class]);

    $now = new DateTimeImmutable('2026-11-01T00:00:00+00:00');
    $acceptUntil = new DateTimeImmutable('2026-12-01T00:00:00+00:00');
    $legacy = (new InMemoryApiKeyRecord(
        publicId: '018f0000-0000-7000-8000-0000000000aa',
        keyPrefix: 'ek_ABCDEFGHI',
        keyHash: 'hash',
        scopes: ['items:read'],
    ))->withTokenVersion(0);
    $canonical = (new InMemoryApiKeyRecord(
        publicId: '018f0000-0000-7000-8000-0000000000bb',
        keyPrefix: 'tst_test_abcdefgh',
        keyHash: 'hash2',
        scopes: ['items:read'],
    ))->withTokenVersion(2);

    $notifiable = new class
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

    $repository = new FakeApiKeyRepository([$legacy, $canonical], $now);
    $gate = new FakeLegacyFormatWarningGate;
    $resolver = new FakeExpiryRecipientResolver([$notifiable]);

    $this->app->instance(FakeApiKeyRepository::class, $repository);
    $this->app->instance(ApiKeyRepository::class, $repository);
    $this->app->instance(ExpiryRecipientResolver::class, $resolver);
    $this->app->instance(LegacyFormatWarningGate::class, $gate);
    $this->app->instance(Clock::class, new FixedClock($now));

    config([
        'api-keys.legacy.accept_until' => $acceptUntil->format(DateTimeInterface::ATOM),
        'api-keys.legacy.warn_days_before' => 90,
        'api-keys.expiry.notice_days' => 7,
        'api-keys.expiry.recipients' => ['owner'],
    ]);

    $this->artisan(NotifyExpiringApiKeysCommand::class)
        ->assertSuccessful();

    Notification::assertSentTo($notifiable, ApiKeyLegacyFormatWarningNotification::class);
    Event::assertDispatched(ApiKeyLegacyFormatWarningSent::class, function (ApiKeyLegacyFormatWarningSent $event) use ($legacy, $acceptUntil): bool {
        return $event->apiKeyId === $legacy->publicId()
            && $event->acceptUntil == $acceptUntil;
    });

    $this->artisan(NotifyExpiringApiKeysCommand::class)
        ->assertSuccessful();

    Notification::assertSentToTimes(
        $notifiable,
        ApiKeyLegacyFormatWarningNotification::class,
        1,
    );
});

it('N2: does not warn before the T−90 window or after accept_until', function (): void {
    Notification::fake();

    $acceptUntil = new DateTimeImmutable('2026-12-01T00:00:00+00:00');
    $legacy = (new InMemoryApiKeyRecord(
        publicId: '018f0000-0000-7000-8000-0000000000cc',
        keyPrefix: 'ek_ABCDEFGHI',
        keyHash: 'hash',
        scopes: ['items:read'],
    ))->withTokenVersion(0);

    $notifiable = new class
    {
        use Notifiable;

        public function getKey(): int
        {
            return 2;
        }

        public function routeNotificationForMail(): string
        {
            return 'owner@example.com';
        }
    };

    $repository = new FakeApiKeyRepository([$legacy]);
    $this->app->instance(ApiKeyRepository::class, $repository);
    $this->app->instance(ExpiryRecipientResolver::class, new FakeExpiryRecipientResolver([$notifiable]));
    $this->app->instance(LegacyFormatWarningGate::class, new FakeLegacyFormatWarningGate);

    config([
        'api-keys.legacy.accept_until' => $acceptUntil->format(DateTimeInterface::ATOM),
        'api-keys.legacy.warn_days_before' => 90,
        'api-keys.expiry.notice_days' => 7,
    ]);

    $this->app->instance(
        Clock::class,
        new FixedClock(new DateTimeImmutable('2026-08-01T00:00:00+00:00')),
    );
    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();
    Notification::assertNothingSent();

    $this->app->instance(
        Clock::class,
        new FixedClock(new DateTimeImmutable('2026-12-01T00:00:00+00:00')),
    );
    $this->artisan(NotifyExpiringApiKeysCommand::class)->assertSuccessful();
    Notification::assertNothingSent();
});
