<?php

declare(strict_types=1);

use Qiick\ApiKeys\Laravel\ApiKeysServiceProvider;
use Qiick\ApiKeys\Notifications\ApiKeyExpiringNotification;
use Qiick\ApiKeys\Notifications\ApiKeyLegacyFormatWarningNotification;

mutates(ApiKeysServiceProvider::class);

/*
 * mergeConfigFrom() merges only the top level: a product that published
 * config/api-keys.php before a nested key existed has the whole `expiry` or
 * `legacy` block, minus the new key. The package must fill the gap with its
 * default instead of leaving it null.
 */
it('fills nested keys missing from a config published before they existed', function (): void {
    config([
        'api-keys.expiry' => ['notice_days' => 3],
        'api-keys.legacy' => ['accept_until' => null],
    ]);

    app()->getProvider(ApiKeysServiceProvider::class)->register();

    expect(config('api-keys.expiry'))->toBe([
        'notice_days' => 3,
        'claim_lease_seconds' => 900,
        'recipients' => ['owner', 'issuer'],
        'notification' => ApiKeyExpiringNotification::class,
    ])
        ->and(config('api-keys.legacy'))->toBe([
            'accept_until' => null,
            'warn_days_before' => 90,
            'warning_notification' => ApiKeyLegacyFormatWarningNotification::class,
        ]);
});

it('keeps every nested value the product set, null and empty lists included', function (): void {
    config([
        'api-keys.expiry' => ['notice_days' => 3, 'claim_lease_seconds' => 60, 'recipients' => [], 'notification' => 'App\\Notifications\\Expiring'],
        'api-keys.legacy' => ['accept_until' => '2027-01-01T00:00:00Z', 'warn_days_before' => 0, 'warning_notification' => null],
    ]);

    app()->getProvider(ApiKeysServiceProvider::class)->register();

    expect(config('api-keys.expiry.claim_lease_seconds'))->toBe(60)
        ->and(config('api-keys.expiry.recipients'))->toBe([])
        ->and(config('api-keys.expiry.notification'))->toBe('App\\Notifications\\Expiring')
        ->and(config('api-keys.legacy.warn_days_before'))->toBe(0)
        ->and(config('api-keys.legacy.warning_notification'))->toBeNull();
});
