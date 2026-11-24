<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Laravel;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Qiick\ApiKeys\AppEnvironmentResolver;
use Qiick\ApiKeys\CacheAttemptLimiter;
use Qiick\ApiKeys\CacheLegacyFormatWarningGate;
use Qiick\ApiKeys\ConfigLifetimePolicy;
use Qiick\ApiKeys\Console\Commands\CheckApiKeysConfigurationCommand;
use Qiick\ApiKeys\Console\Commands\NotifyExpiringApiKeysCommand;
use Qiick\ApiKeys\Contracts\AttemptLimiter;
use Qiick\ApiKeys\Contracts\Clock;
use Qiick\ApiKeys\Contracts\EnvironmentResolver;
use Qiick\ApiKeys\Contracts\LegacyFormatWarningGate;
use Qiick\ApiKeys\Contracts\LifetimePolicy;
use Qiick\ApiKeys\Contracts\RandomSource;
use Qiick\ApiKeys\LegacyCutoff;
use Qiick\ApiKeys\LegacyTokenMatcher;
use Qiick\ApiKeys\RandomBytesSource;
use Qiick\ApiKeys\RotationService;
use Qiick\ApiKeys\SystemClock;
use Qiick\ApiKeys\TokenCodec;
use Qiick\ApiKeys\TokenEnvironment;

/**
 * Registers the package in a Laravel app. Auto-discovered through
 * `extra.laravel.providers` in composer.json.
 *
 * Products bind ApiKeyRepository, KeyAuthorizer, ScopeVocabulary and
 * ExpiryRecipientResolver themselves. No HTTP middleware ships; the expiry
 * command is registered here.
 */
final class ApiKeysServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../../config/api-keys.php', 'api-keys');

        $this->app->singleton(Clock::class, SystemClock::class);
        $this->app->singleton(RandomSource::class, RandomBytesSource::class);
        $this->app->singleton(LegacyFormatWarningGate::class, CacheLegacyFormatWarningGate::class);

        // The default cache store must be redis or memcached (array in tests); a product binding wins.
        $this->app->singletonIf(
            AttemptLimiter::class,
            fn (Application $app): AttemptLimiter => new CacheAttemptLimiter($app->make(CacheRepository::class)),
        );

        $this->app->singleton(EnvironmentResolver::class, function (Application $app): EnvironmentResolver {
            $configured = $this->config($app)->get('api-keys.environment');

            if (is_string($configured) && $configured !== '') {
                $environment = TokenEnvironment::tryFrom($configured);
                if ($environment === null) {
                    throw new \InvalidArgumentException(
                        'api-keys.environment must be "live" or "test" when set.'
                    );
                }

                return new AppEnvironmentResolver($environment === TokenEnvironment::Live);
            }

            return new AppEnvironmentResolver($app->environment('production'));
        });

        $this->app->singleton(TokenCodec::class, function (Application $app): TokenCodec {
            $productPrefix = $this->config($app)->get('api-keys.product_prefix');
            if (! is_string($productPrefix) || $productPrefix === '') {
                throw new \InvalidArgumentException(
                    'api-keys.product_prefix must be set to a three-letter product code before issuing tokens.'
                );
            }

            $legacyMatchers = $this->config($app)->get('api-keys.legacy_matchers', []);
            if (! is_array($legacyMatchers)) {
                $legacyMatchers = [];
            }

            $legacyAcceptUntil = $this->validatedLegacyAcceptUntil($app);
            $tokenVersion = $this->config($app)->get('api-keys.token_version', TokenCodec::DEFAULT_TOKEN_VERSION);
            if (! is_int($tokenVersion) || ($tokenVersion !== 1 && $tokenVersion !== 2)) {
                throw new \InvalidArgumentException(
                    'api-keys.token_version must be 1 or 2.'
                );
            }

            return new TokenCodec(
                productPrefix: $productPrefix,
                environment: $app->make(EnvironmentResolver::class),
                random: $app->make(RandomSource::class),
                legacyMatchers: $this->resolveLegacyMatchers($app, $legacyMatchers),
                legacyAcceptUntil: $legacyAcceptUntil,
                defaultTokenVersion: $tokenVersion,
            );
        });

        $this->app->singleton(RotationService::class, function (Application $app): RotationService {
            $max = $this->config($app)->get(
                'api-keys.rotation_max_grace_hours',
                RotationService::DEFAULT_MAX_GRACE_HOURS,
            );

            return new RotationService(
                is_int($max) ? $max : RotationService::DEFAULT_MAX_GRACE_HOURS,
                $app->make(LifetimePolicy::class),
            );
        });

        // A product's own policy (bound before this provider, or after it) wins.
        $this->app->singletonIf(
            LifetimePolicy::class,
            fn (Application $app): LifetimePolicy => new ConfigLifetimePolicy($this->validatedMaxLifetimeDays($app)),
        );
    }

    public function boot(): void
    {
        $this->validateConfiguration();

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../../config/api-keys.php' => config_path('api-keys.php'),
            ], 'api-keys-config');

            $this->commands([
                NotifyExpiringApiKeysCommand::class,
                CheckApiKeysConfigurationCommand::class,
            ]);
        }
    }

    /**
     * Fails fast on settings that would otherwise be read wrong at runtime.
     * Runs at boot and from `api-keys:check`. The cache store behind the
     * attempt limiter is deliberately not checked here: an unsupported store
     * must not break every artisan command (package:discover, migrations,
     * product tests); it fails when the limiter is first resolved, and
     * `api-keys:check` reports it for deploy pipelines.
     *
     * @throws \InvalidArgumentException|\RuntimeException
     */
    public function validateConfiguration(): void
    {
        $this->validatedLegacyAcceptUntil();
        $this->validatedMaxLifetimeDays();
        $this->assertWholeNumberAtLeast('api-keys.failed_attempts_per_minute', 'API_KEYS_FAILED_ATTEMPTS_PER_MINUTE', 0);
        $this->assertWholeNumberAtLeast('api-keys.expiry.claim_lease_seconds', 'API_KEYS_EXPIRY_CLAIM_LEASE_SECONDS', 1);
    }

    private function config(Application $app): ConfigRepository
    {
        return $app->make(ConfigRepository::class);
    }

    /**
     * Validate the legacy accept-until configuration at application start.
     *
     * A bad value fails during boot rather than lazily on first TokenCodec resolve.
     */
    private function validatedLegacyAcceptUntil(?Application $app = null): ?\DateTimeImmutable
    {
        $application = $app ?? $this->app;
        $legacyMatchers = $this->config($application)->get('api-keys.legacy_matchers', []);
        if (! is_array($legacyMatchers)) {
            $legacyMatchers = [];
        }

        $acceptUntil = LegacyCutoff::parse($this->config($application)->get('api-keys.legacy.accept_until'));

        if ($acceptUntil === null && $legacyMatchers !== []) {
            throw new \RuntimeException(
                'api-keys.legacy.accept_until (API_KEYS_LEGACY_ACCEPT_UNTIL) is required when legacy_matchers is non-empty.'
            );
        }

        return $acceptUntil;
    }

    /**
     * Validate `api-keys.max_lifetime_days` at application start.
     *
     * Unset (null or empty) disables the policy. Anything else must be a whole
     * number of days >= 1: a typo such as `30abc` or `thirty` would otherwise
     * be cast to 30 or to 0 and silently change or switch off enforcement.
     */
    private function validatedMaxLifetimeDays(?Application $app = null): ?int
    {
        $configured = $this->config($app ?? $this->app)->get('api-keys.max_lifetime_days');

        if ($configured === null || $configured === '') {
            return null;
        }

        $days = $this->wholeNumber($configured) ?? 0;

        if ($days < 1) {
            throw new \InvalidArgumentException(
                'api-keys.max_lifetime_days (API_KEYS_MAX_LIFETIME_DAYS) must be a whole number of days >= 1, or unset to disable.',
            );
        }

        return $days;
    }

    /**
     * A setting read raw from the environment must be a whole number of at
     * least `$minimum`; a typo such as `twenty` would otherwise be cast to 0
     * and silently switch the setting off.
     *
     * @throws \InvalidArgumentException
     */
    private function assertWholeNumberAtLeast(string $key, string $envName, int $minimum): void
    {
        $value = $this->wholeNumber($this->config($this->app)->get($key));

        if ($value === null || $value < $minimum) {
            throw new \InvalidArgumentException("{$key} ({$envName}) must be a whole number >= {$minimum}.");
        }
    }

    /**
     * Digits only: filter_var() would also accept " 30" and "+30".
     */
    private function wholeNumber(mixed $configured): ?int
    {
        if (is_int($configured)) {
            return $configured;
        }

        return is_string($configured) && preg_match('/^(0|[1-9][0-9]*)$/D', $configured) === 1 ? (int) $configured : null;
    }

    /**
     * @param  array<mixed>  $legacyMatchers
     * @return list<LegacyTokenMatcher>
     */
    private function resolveLegacyMatchers(Application $app, array $legacyMatchers): array
    {
        $resolved = [];

        foreach ($legacyMatchers as $matcher) {
            if (is_string($matcher)) {
                $instance = $app->make($matcher);
                if (! $instance instanceof LegacyTokenMatcher) {
                    throw new \InvalidArgumentException(
                        'api-keys.legacy_matchers entries must resolve to LegacyTokenMatcher instances.'
                    );
                }
                $resolved[] = $instance;

                continue;
            }

            if ($matcher instanceof LegacyTokenMatcher) {
                $resolved[] = $matcher;
            }
        }

        return $resolved;
    }
}
