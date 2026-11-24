<?php

declare(strict_types=1);

use Qiick\ApiKeys\ConfigLifetimePolicy;
use Qiick\ApiKeys\Contracts\AttemptLimiter;
use Qiick\ApiKeys\Contracts\LifetimePolicy;
use Qiick\ApiKeys\Laravel\ApiKeysServiceProvider;
use Qiick\ApiKeys\RotationService;
use Qiick\ApiKeys\Testing\FixedClock;
use Qiick\ApiKeys\Testing\InMemoryApiKeyRecord;
use Qiick\ApiKeys\Tests\Support\RegexLegacyTokenMatcher;
use Qiick\ApiKeys\TokenCodec;

it('merges the package defaults into the api-keys config', function (): void {
    expect(config('api-keys'))->toMatchArray([
        'product_prefix' => 'tst',
        'environment' => null,
        'rotation_grace_hours' => 24,
        'rotation_max_grace_hours' => 168,
        'usage_throttle_seconds' => 60,
        'usage_bypass_throttle_on_ip_change' => true,
        'default_rate_limit_per_minute' => 60,
        'failed_attempts_per_minute' => 20,
        'legacy_matchers' => [],
    ]);

    expect(config('api-keys.legacy.accept_until'))->toBeNull();
});

it('binds RotationService with config rotation_max_grace_hours', function (): void {
    config(['api-keys.rotation_max_grace_hours' => 48]);

    $service = app(RotationService::class);

    expect($service)->toBeInstanceOf(RotationService::class)
        ->and($service->maxGraceHours())->toBe(48)
        ->and(app(RotationService::class))->toBe($service);
});

it('lets an app publish the config file', function (): void {
    $this->artisan('vendor:publish', ['--tag' => 'api-keys-config', '--force' => true])
        ->assertSuccessful();

    expect(config_path('api-keys.php'))->toBeFile();

    unlink(config_path('api-keys.php'));
});

it('fails boot when legacy_matchers is set without API_KEYS_LEGACY_ACCEPT_UNTIL', function (): void {
    config([
        'api-keys.product_prefix' => 'tst',
        'api-keys.legacy_matchers' => [RegexLegacyTokenMatcher::class],
        'api-keys.legacy.accept_until' => null,
    ]);

    $provider = app()->getProvider(ApiKeysServiceProvider::class);

    expect(fn () => $provider->boot())
        ->toThrow(RuntimeException::class, 'API_KEYS_LEGACY_ACCEPT_UNTIL');
});

it('fails boot when API_KEYS_LEGACY_ACCEPT_UNTIL is not an absolute ISO-8601 timestamp', function (): void {
    config([
        'api-keys.product_prefix' => 'tst',
        'api-keys.legacy_matchers' => [RegexLegacyTokenMatcher::class],
        'api-keys.legacy.accept_until' => 'not-a-date',
    ]);

    $provider = app()->getProvider(ApiKeysServiceProvider::class);

    expect(fn () => $provider->boot())
        ->toThrow(RuntimeException::class, 'DATE_ATOM');
});

it('rejects relative accept_until strings at boot', function (string $relative): void {
    config([
        'api-keys.product_prefix' => 'tst',
        'api-keys.legacy_matchers' => [RegexLegacyTokenMatcher::class],
        'api-keys.legacy.accept_until' => $relative,
    ]);

    $provider = app()->getProvider(ApiKeysServiceProvider::class);

    expect(fn () => $provider->boot())
        ->toThrow(RuntimeException::class, 'DATE_ATOM');
})->with([
    'now',
    'tomorrow',
    '+10 years',
]);

it('rejects date-only accept_until values at boot', function (): void {
    config([
        'api-keys.product_prefix' => 'tst',
        'api-keys.legacy_matchers' => [RegexLegacyTokenMatcher::class],
        'api-keys.legacy.accept_until' => '2027-01-01',
    ]);

    $provider = app()->getProvider(ApiKeysServiceProvider::class);

    expect(fn () => $provider->boot())
        ->toThrow(RuntimeException::class, 'DATE_ATOM');
});

it('fails at application start for an invalid accept_until without resolving TokenCodec', function (): void {
    config([
        'api-keys.product_prefix' => 'tst',
        'api-keys.legacy_matchers' => [RegexLegacyTokenMatcher::class],
        'api-keys.legacy.accept_until' => '2027-01-01T00:00:00',
    ]);

    app()->forgetInstance(TokenCodec::class);
    $provider = app()->getProvider(ApiKeysServiceProvider::class);

    expect(fn () => $provider->boot())
        ->toThrow(RuntimeException::class, 'DATE_ATOM');
});

it('accepts the UTC Z form in api-keys.legacy.accept_until at boot', function (): void {
    config([
        'api-keys.product_prefix' => 'tst',
        'api-keys.legacy_matchers' => [],
        'api-keys.legacy.accept_until' => '2027-01-01T00:00:00Z',
    ]);

    $provider = app()->getProvider(ApiKeysServiceProvider::class);

    expect(fn () => $provider->boot())->not->toThrow(RuntimeException::class);

    config([
        'api-keys.legacy_matchers' => [RegexLegacyTokenMatcher::class],
        'api-keys.legacy.accept_until' => '2027-01-01T00:00:00Z',
    ]);

    app()->forgetInstance(TokenCodec::class);
    app()->bind(RegexLegacyTokenMatcher::class, fn () => RegexLegacyTokenMatcher::externaEkStyle(
        new DateTimeImmutable('2027-01-01T00:00:00Z'),
    ));

    expect(fn () => $provider->boot())->not->toThrow(RuntimeException::class)
        ->and(app(TokenCodec::class))->toBeInstanceOf(TokenCodec::class);
});

it('boots when accept_until is an absolute DATE_ATOM timestamp', function (): void {
    config([
        'api-keys.product_prefix' => 'tst',
        'api-keys.legacy_matchers' => [],
        'api-keys.legacy.accept_until' => '2027-01-01T00:00:00+00:00',
    ]);

    $provider = app()->getProvider(ApiKeysServiceProvider::class);

    // Empty matchers: codec boots without requiring accept_until.
    expect(fn () => $provider->boot())->not->toThrow(RuntimeException::class);
    app()->forgetInstance(TokenCodec::class);
    expect(app(TokenCodec::class))->toBeInstanceOf(TokenCodec::class);

    config([
        'api-keys.legacy_matchers' => [RegexLegacyTokenMatcher::class],
        'api-keys.legacy.accept_until' => '2027-01-01T00:00:00+00:00',
    ]);
    app()->forgetInstance(TokenCodec::class);

    // RegexLegacyTokenMatcher needs acceptUntil via container — bind a fixture.
    app()->bind(RegexLegacyTokenMatcher::class, fn () => RegexLegacyTokenMatcher::externaEkStyle(
        new DateTimeImmutable('2027-01-01T00:00:00+00:00'),
    ));

    expect(fn () => $provider->boot())->not->toThrow(RuntimeException::class)
        ->and(app(TokenCodec::class))->toBeInstanceOf(TokenCodec::class);
});

it('enforces api-keys.max_lifetime_days on rotation without a product binding', function (): void {
    config(['api-keys.max_lifetime_days' => '30']);
    app()->forgetInstance(RotationService::class);

    $now = new DateTimeImmutable('2026-01-15T12:00:00+00:00');
    $codec = app(TokenCodec::class);
    $issued = $codec->issue();
    $record = (new InMemoryApiKeyRecord(
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read'],
    ))->withExpiresAt($now->modify('+365 days'));

    expect(app(LifetimePolicy::class))->toBeInstanceOf(ConfigLifetimePolicy::class)
        ->and(fn () => app(RotationService::class)->rotate($record, $codec, new FixedClock($now), 0))
        ->toThrow(InvalidArgumentException::class, 'lifetime policy');
});

it('keeps a product LifetimePolicy binding over the config default', function (): void {
    config(['api-keys.max_lifetime_days' => '30']);
    $productPolicy = new ConfigLifetimePolicy(null);
    app()->instance(LifetimePolicy::class, $productPolicy);
    app()->forgetInstance(RotationService::class);

    $now = new DateTimeImmutable('2026-01-15T12:00:00+00:00');
    $codec = app(TokenCodec::class);
    $issued = $codec->issue();
    $record = (new InMemoryApiKeyRecord(
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read'],
    ))->withExpiresAt($now->modify('+365 days'));

    $rotation = app(RotationService::class)->rotate($record, $codec, new FixedClock($now), 0);

    expect(app(LifetimePolicy::class))->toBe($productPolicy)
        ->and($rotation->lastRotatedAt)->toEqual($now);
});

it('fails boot when api-keys.max_lifetime_days is not a whole number of days >= 1', function (mixed $configured): void {
    config(['api-keys.max_lifetime_days' => $configured]);

    $provider = app()->getProvider(ApiKeysServiceProvider::class);

    expect(fn () => $provider->boot())
        ->toThrow(InvalidArgumentException::class, 'API_KEYS_MAX_LIFETIME_DAYS');
})->with([
    'trailing garbage' => '30abc',
    'not a number' => 'thirty',
    'zero' => '0',
    'negative' => -5,
    'fraction' => '1.5',
    'leading space' => ' 30',
    'explicit plus sign' => '+30',
    'leading zero' => '030',
]);

it('boots with max_lifetime_days unset and allows any expiry', function (): void {
    config(['api-keys.max_lifetime_days' => null]);

    app()->getProvider(ApiKeysServiceProvider::class)->boot();

    expect(app(LifetimePolicy::class)->allowsExpiry(null, new DateTimeImmutable))->toBeTrue();
});

it('fails boot when a brake or lease setting is not a whole number', function (string $key, mixed $configured): void {
    config([$key => $configured]);

    expect(fn () => app()->getProvider(ApiKeysServiceProvider::class)->boot())
        ->toThrow(InvalidArgumentException::class, $key);
})->with([
    'brake typo' => ['api-keys.failed_attempts_per_minute', 'twenty'],
    'brake trailing garbage' => ['api-keys.failed_attempts_per_minute', '20abc'],
    'brake negative' => ['api-keys.failed_attempts_per_minute', '-1'],
    'brake padded' => ['api-keys.failed_attempts_per_minute', ' 20'],
    'brake empty' => ['api-keys.failed_attempts_per_minute', ''],
    'lease zero' => ['api-keys.expiry.claim_lease_seconds', '0'],
    'lease typo' => ['api-keys.expiry.claim_lease_seconds', '15min'],
]);

it('boots with digit-only brake and lease settings from the environment', function (): void {
    config([
        'api-keys.failed_attempts_per_minute' => '0',
        'api-keys.expiry.claim_lease_seconds' => '600',
    ]);

    app()->getProvider(ApiKeysServiceProvider::class)->boot();

    expect(true)->toBeTrue();
});

it('fails boot when the default cache store cannot back the attempt limiter', function (): void {
    config(['cache.default' => 'database']);
    app()->forgetInstance('cache.store');
    app()->forgetInstance(AttemptLimiter::class);

    expect(fn () => app()->getProvider(ApiKeysServiceProvider::class)->boot())
        ->toThrow(InvalidArgumentException::class, 'cannot increment atomically');
});
