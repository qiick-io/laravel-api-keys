<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Schema;
use Qiick\ApiKeys\CacheAttemptLimiter;
use Qiick\ApiKeys\ConfigLifetimePolicy;
use Qiick\ApiKeys\Contracts\AttemptLimiter;
use Qiick\ApiKeys\Contracts\EnvironmentResolver;
use Qiick\ApiKeys\Contracts\LifetimePolicy;
use Qiick\ApiKeys\DatabaseAttemptLimiter;
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
        'attempt_limiter' => 'auto',
        'attempt_limiter_table' => 'api_key_attempts',
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

it('boots on an unsupported cache store, so artisan and package discovery keep working', function (): void {
    useDefaultCacheStore('database');
    config(['api-keys.attempt_limiter' => 'cache']);

    app()->getProvider(ApiKeysServiceProvider::class)->boot();

    expect(fn () => app(AttemptLimiter::class))
        ->toThrow(InvalidArgumentException::class, 'cannot increment atomically');
});

it('reports an unsupported cache store from api-keys:check, for deploy pipelines', function (): void {
    useDefaultCacheStore('database');
    config(['api-keys.attempt_limiter' => 'cache']);

    $this->artisan('api-keys:check')
        ->expectsOutputToContain('cannot increment atomically')
        ->assertFailed();
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

function createReferenceAttemptsTable(): void
{
    Schema::create('api_key_attempts', function (Blueprint $blueprint): void {
        $blueprint->string('bucket', 255)->primary();
        $blueprint->unsignedInteger('hits')->default(0);
        $blueprint->unsignedBigInteger('expires_at')->index();
    });
}

it('picks the attempt limiter from the cache store when set to auto', function (string $store, string $limiterClass): void {
    config(['cache.stores.file.path' => sys_get_temp_dir()]);
    useDefaultCacheStore($store);

    expect(config('api-keys.attempt_limiter'))->toBe('auto')
        ->and(app(AttemptLimiter::class))->toBeInstanceOf($limiterClass);
})->with([
    'redis' => ['redis', CacheAttemptLimiter::class],
    'memcached' => ['memcached', CacheAttemptLimiter::class],
    'array (tests)' => ['array', CacheAttemptLimiter::class],
    'database' => ['database', DatabaseAttemptLimiter::class],
    'file' => ['file', DatabaseAttemptLimiter::class],
]);

it('honours an explicit attempt limiter whatever the cache store', function (): void {
    useDefaultCacheStore('redis');
    config(['api-keys.attempt_limiter' => 'database', 'api-keys.attempt_limiter_table' => 'custom_attempts']);

    $limiter = app(AttemptLimiter::class);

    expect($limiter)->toBeInstanceOf(DatabaseAttemptLimiter::class)
        ->and($limiter->table())->toBe('custom_attempts')
        ->and(app(DatabaseAttemptLimiter::class))->toBe($limiter);

    useDefaultCacheStore('array');
    config(['api-keys.attempt_limiter' => 'cache']);

    expect(app(AttemptLimiter::class))->toBeInstanceOf(CacheAttemptLimiter::class);
});

it('fails at boot on an unknown attempt limiter', function (mixed $value): void {
    config(['api-keys.attempt_limiter' => $value]);

    expect(fn () => app()->getProvider(ApiKeysServiceProvider::class)->boot())
        ->toThrow(InvalidArgumentException::class, 'api-keys.attempt_limiter must be auto, cache or database.');

    useDefaultCacheStore('array');

    expect(fn () => app(AttemptLimiter::class))
        ->toThrow(InvalidArgumentException::class, 'api-keys.attempt_limiter must be auto, cache or database.');
})->with(['redis', '', null]);

it('fails at boot on an empty attempt limiter table name', function (): void {
    config(['api-keys.attempt_limiter_table' => '']);

    expect(fn () => app()->getProvider(ApiKeysServiceProvider::class)->boot())
        ->toThrow(InvalidArgumentException::class, 'api-keys.attempt_limiter_table must be a table name.');
});

it('names the active cache limiter in api-keys:check', function (): void {
    useDefaultCacheStore('array');

    $this->artisan('api-keys:check')
        ->expectsOutputToContain('Attempt limiter: cache (array store).')
        ->expectsOutputToContain('API keys configuration is ready')
        ->assertSuccessful();
});

it('names the active database limiter and its table in api-keys:check', function (): void {
    createReferenceAttemptsTable();
    useDefaultCacheStore('database');

    $this->artisan('api-keys:check')
        ->expectsOutputToContain('Attempt limiter: database (table api_key_attempts).')
        ->expectsOutputToContain('API keys configuration is ready')
        ->assertSuccessful();
});

it('fails api-keys:check when the database limiter has no table', function (): void {
    useDefaultCacheStore('database');

    $this->artisan('api-keys:check')
        ->expectsOutputToContain('The api_key_attempts table is missing: create it as docs/reference-schema.md describes.')
        ->assertFailed();
});

it('prunes ended attempt windows with api-keys:prune-attempts', function (): void {
    createReferenceAttemptsTable();
    useDefaultCacheStore('database');
    $this->freezeTime();
    $limiter = app(DatabaseAttemptLimiter::class);
    $limiter->hit('ended', 10);
    $limiter->hit('live', 60);
    $this->travel(10)->seconds();

    $this->artisan('api-keys:prune-attempts')
        ->expectsOutputToContain('Pruned 1 ended attempt windows.')
        ->assertSuccessful();

    expect(DB::table('api_key_attempts')->pluck('bucket')->all())->toBe(['live']);
});

it('fails api-keys:prune-attempts when the table is missing', function (): void {
    useDefaultCacheStore('database');

    $this->artisan('api-keys:prune-attempts')
        ->expectsOutputToContain('The api_key_attempts table is missing')
        ->assertFailed();
});

it('names an attempt limiter the application bound in api-keys:check', function (): void {
    app()->instance(AttemptLimiter::class, new FakeAttemptLimiter);

    $this->artisan('api-keys:check')
        ->expectsOutputToContain('Attempt limiter: '.FakeAttemptLimiter::class.' (bound by the application).')
        ->assertSuccessful();
});

it('prunes the table of the attempt limiter the application bound', function (): void {
    Schema::create('tenant_attempts', function (Blueprint $blueprint): void {
        $blueprint->string('bucket', 255)->primary();
        $blueprint->unsignedInteger('hits')->default(0);
        $blueprint->unsignedBigInteger('expires_at')->index();
    });
    $this->freezeTime();
    $limiter = new DatabaseAttemptLimiter(DB::connection(), 'tenant_attempts');
    app()->instance(AttemptLimiter::class, $limiter);
    $limiter->hit('ended', 10);
    $this->travel(10)->seconds();

    $this->artisan('api-keys:prune-attempts')
        ->expectsOutputToContain('Pruned 1 ended attempt windows.')
        ->assertSuccessful();
});

it('has nothing to prune when the attempt limiter is the cache', function (): void {
    useDefaultCacheStore('array');

    $this->artisan('api-keys:prune-attempts')
        ->expectsOutputToContain('The attempt limiter does not use the database: nothing to prune.')
        ->assertSuccessful();
});
