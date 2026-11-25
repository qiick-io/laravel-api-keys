<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\File;
use Qiick\ApiKeys\CacheAttemptLimiter;
use Qiick\ApiKeys\ConfigLifetimePolicy;
use Qiick\ApiKeys\Contracts\AttemptLimiter;
use Qiick\ApiKeys\Contracts\EnvironmentResolver;
use Qiick\ApiKeys\Contracts\LifetimePolicy;
use Qiick\ApiKeys\FailedAttemptLimiter;
use Qiick\ApiKeys\Laravel\ApiKeysServiceProvider;
use Qiick\ApiKeys\RotationService;
use Qiick\ApiKeys\Testing\FakeAttemptLimiter;
use Qiick\ApiKeys\Testing\FixedClock;
use Qiick\ApiKeys\Testing\InMemoryApiKeyRecord;
use Qiick\ApiKeys\Tests\Support\RegexLegacyTokenMatcher;
use Qiick\ApiKeys\TokenCodec;

mutates(ApiKeysServiceProvider::class);

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
        'cache_store' => null,
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
    $published = config_path('api-keys.php');

    try {
        $this->artisan('vendor:publish', ['--tag' => 'api-keys-config', '--force' => true])
            ->assertSuccessful();

        expect($published)->toBeFile()
            ->and(file_get_contents($published))->toBe(file_get_contents(dirname(__DIR__, 2).'/config/api-keys.php'));
    } finally {
        // A mutated provider can publish a directory here; leaving it behind would
        // break every later run that loads Testbench's config directory.
        is_dir($published) ? File::deleteDirectory($published) : @unlink($published);
    }
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

it('boots with max_lifetime_days unset and allows any expiry', function (mixed $unset): void {
    config(['api-keys.max_lifetime_days' => $unset]);

    app()->getProvider(ApiKeysServiceProvider::class)->boot();

    expect(app(LifetimePolicy::class)->allowsExpiry(null, new DateTimeImmutable))->toBeTrue();
})->with(['null' => [null], 'empty' => ['']]);

it('fails boot when a brake or lease setting is not a whole number', function (string $key, mixed $configured): void {
    config([$key => $configured]);

    expect(fn () => app()->getProvider(ApiKeysServiceProvider::class)->boot())
        ->toThrow(InvalidArgumentException::class, $key);
})->with([
    'brake typo' => ['api-keys.failed_attempts_per_minute', 'twenty'],
    'brake trailing garbage' => ['api-keys.failed_attempts_per_minute', '20abc'],
    'brake negative' => ['api-keys.failed_attempts_per_minute', '-1'],
    'brake negative integer' => ['api-keys.failed_attempts_per_minute', -1],
    'brake padded' => ['api-keys.failed_attempts_per_minute', ' 20'],
    'brake empty' => ['api-keys.failed_attempts_per_minute', ''],
    'lease zero' => ['api-keys.expiry.claim_lease_seconds', '0'],
    'lease typo' => ['api-keys.expiry.claim_lease_seconds', '15min'],
    'warning window negative' => ['api-keys.legacy.warn_days_before', '-1'],
    'warning window negative integer' => ['api-keys.legacy.warn_days_before', -1],
    'warning window typo' => ['api-keys.legacy.warn_days_before', 'ninety'],
]);

it('boots with digit-only brake, lease and warning settings at their smallest values', function (): void {
    config([
        'api-keys.failed_attempts_per_minute' => '0',
        'api-keys.expiry.claim_lease_seconds' => '1',
        'api-keys.legacy.warn_days_before' => '0',
        'api-keys.max_lifetime_days' => '1',
    ]);

    app()->getProvider(ApiKeysServiceProvider::class)->boot();

    expect(app()->getProvider(ApiKeysServiceProvider::class)->wholeNumberSetting('api-keys.expiry.claim_lease_seconds', 1))->toBe(1);
});

/**
 * Points the default cache store at `$store` and drops anything resolved from the old one.
 */
function useDefaultCacheStore(string $store): void
{
    config(['cache.default' => $store]);
    app()->forgetInstance('cache.store');
    app()->forgetInstance(AttemptLimiter::class);
}

it('counts attempts with Laravel\'s RateLimiter on the default cache store, or on api-keys.cache_store', function (): void {
    useDefaultCacheStore('array');
    $limiter = app(AttemptLimiter::class);
    $limiter->hit('bucket');

    expect($limiter)->toBeInstanceOf(CacheAttemptLimiter::class)
        ->and(Cache::store('array')->get('bucket'))->toBe(1);

    config(['api-keys.cache_store' => 'file', 'cache.stores.file.path' => sys_get_temp_dir().'/api-keys-cache-store-test']);
    app()->forgetInstance(AttemptLimiter::class);
    Cache::store('file')->flush();
    app(AttemptLimiter::class)->hit('bucket');
    app(AttemptLimiter::class)->hit('bucket');

    expect(Cache::store('file')->get('bucket'))->toBe(2)
        ->and(Cache::store('array')->get('bucket'))->toBe(1);
});

it('fails at boot on an api-keys.cache_store that is not a store name', function (mixed $value): void {
    config(['api-keys.cache_store' => $value]);

    expect(fn () => app()->getProvider(ApiKeysServiceProvider::class)->boot())
        ->toThrow(InvalidArgumentException::class, 'api-keys.cache_store must be a cache store name, or null for the default store.');

    useDefaultCacheStore('array');

    expect(fn () => app(AttemptLimiter::class))
        ->toThrow(InvalidArgumentException::class, 'api-keys.cache_store must be a cache store name, or null for the default store.');
})->with(['', 0, false]);

it('fails api-keys:check on the null cache store, which would switch the limits off', function (): void {
    config(['cache.stores.none' => ['driver' => 'null'], 'api-keys.cache_store' => 'none']);
    app()->forgetInstance(AttemptLimiter::class);

    $this->artisan('api-keys:check')
        ->expectsOutputToContain('The null cache store keeps no attempt counters')
        ->assertFailed();
});

it('warns from api-keys:check on the file cache store, which is not atomic across workers', function (): void {
    config(['cache.stores.file.path' => sys_get_temp_dir().'/api-keys-cache-store-test']);
    useDefaultCacheStore('file');

    $this->artisan('api-keys:check')
        ->expectsOutputToContain('The file cache store does not increment atomically')
        ->expectsOutputToContain('Attempt limiter: Laravel RateLimiter on the file cache store.')
        ->expectsOutputToContain('API keys configuration is ready')
        ->assertSuccessful();
});

it('warns from api-keys:check on the array cache store outside tests only', function (): void {
    useDefaultCacheStore('array');

    $this->artisan('api-keys:check')
        ->doesntExpectOutputToContain('array cache store keeps')
        ->expectsOutputToContain('Attempt limiter: Laravel RateLimiter on the array cache store.')
        ->assertSuccessful();

    app()->detectEnvironment(fn (): string => 'production');

    $this->artisan('api-keys:check')
        ->expectsOutputToContain('The array cache store keeps attempt counters per process')
        ->assertSuccessful();
});

it('raises no store warning on an atomic store', function (): void {
    useDefaultCacheStore('database');

    $this->artisan('api-keys:check')
        ->doesntExpectOutputToContain('does not increment atomically')
        ->doesntExpectOutputToContain('keeps attempt counters per process')
        ->expectsOutputToContain('Attempt limiter: Laravel RateLimiter on the database cache store.')
        ->assertSuccessful();
});

it('names an attempt limiter the application bound in api-keys:check', function (): void {
    app()->instance(AttemptLimiter::class, new FakeAttemptLimiter);

    $this->artisan('api-keys:check')
        ->expectsOutputToContain('Attempt limiter: '.FakeAttemptLimiter::class.' (bound by the application).')
        ->assertSuccessful();
});

it('passes api-keys:check when the limiter and the settings are usable', function (): void {
    useDefaultCacheStore('array');

    $this->artisan('api-keys:check')
        ->expectsOutputToContain('API keys configuration is ready')
        ->assertSuccessful();
});

it('reports an invalid setting from api-keys:check', function (): void {
    useDefaultCacheStore('array');
    config(['api-keys.failed_attempts_per_minute' => 'twenty']);

    $this->artisan('api-keys:check')
        ->expectsOutputToContain('API_KEYS_FAILED_ATTEMPTS_PER_MINUTE')
        ->assertFailed();
});

it('fails api-keys:check when the application timezone is not UTC', function (): void {
    useDefaultCacheStore('array');
    config(['app.timezone' => 'Europe/Rome']);

    $this->artisan('api-keys:check')
        ->expectsOutputToContain('app.timezone must be UTC')
        ->assertFailed();
});

it('reports an unusable codec setting from api-keys:check', function (string $key, mixed $value, string $message): void {
    useDefaultCacheStore('array');
    config([$key => $value]);
    app()->forgetInstance(TokenCodec::class);
    app()->forgetInstance(EnvironmentResolver::class);

    $this->artisan('api-keys:check')
        ->expectsOutputToContain($message)
        ->assertFailed();
})->with([
    'empty product prefix' => ['api-keys.product_prefix', '', 'api-keys.product_prefix must be set'],
    'unknown token version' => ['api-keys.token_version', 3, 'api-keys.token_version must be 1 or 2.'],
    'unknown environment' => ['api-keys.environment', 'foo', 'api-keys.environment must be "live" or "test" when set.'],
]);

it('builds the failed-attempt brake from api-keys.failed_attempts_per_minute', function (mixed $configured, int $blockedAfter): void {
    config(['api-keys.failed_attempts_per_minute' => $configured, 'cache.default' => 'array']);
    app()->forgetInstance('cache.store');
    app()->forgetInstance(AttemptLimiter::class);
    app()->forgetInstance(FailedAttemptLimiter::class);

    $brake = app(FailedAttemptLimiter::class);
    $countedBeforeBlock = 0;

    while (! $brake->isBlocked('203.0.113.10') && $countedBeforeBlock < 10) {
        $brake->countFailure('203.0.113.10');
        $countedBeforeBlock++;
    }

    expect($brake->maxPerMinute())->toBe((int) $configured)
        ->and($countedBeforeBlock)->toBe($blockedAfter);
})->with([
    'off' => ['0', 10],
    'five' => ['5', 5],
]);
