<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Laravel;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Qiick\ApiKeys\AppEnvironmentResolver;
use Qiick\ApiKeys\Contracts\Clock;
use Qiick\ApiKeys\Contracts\EnvironmentResolver;
use Qiick\ApiKeys\Contracts\RandomSource;
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
 * Products bind ApiKeyRepository, KeyAuthorizer and ScopeVocabulary themselves.
 * No HTTP middleware or Artisan commands ship with this package.
 */
final class ApiKeysServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../../config/api-keys.php', 'api-keys');

        $this->app->singleton(Clock::class, SystemClock::class);
        $this->app->singleton(RandomSource::class, RandomBytesSource::class);

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

            return new AppEnvironmentResolver((bool) $app->environment('production'));
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

            if ($legacyMatchers !== []) {
                $acceptUntil = $this->config($app)->get('api-keys.legacy.accept_until');
                if (! is_string($acceptUntil) || $acceptUntil === '') {
                    throw new \RuntimeException(
                        'api-keys.legacy.accept_until (API_KEYS_LEGACY_ACCEPT_UNTIL) is required when legacy_matchers is non-empty.'
                    );
                }
            }

            return new TokenCodec(
                productPrefix: $productPrefix,
                environment: $app->make(EnvironmentResolver::class),
                random: $app->make(RandomSource::class),
                legacyMatchers: $this->resolveLegacyMatchers($app, $legacyMatchers),
            );
        });

        $this->app->singleton(RotationService::class, function (Application $app): RotationService {
            $max = $this->config($app)->get(
                'api-keys.rotation_max_grace_hours',
                RotationService::DEFAULT_MAX_GRACE_HOURS,
            );

            return new RotationService(
                is_int($max) ? $max : RotationService::DEFAULT_MAX_GRACE_HOURS,
            );
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../../config/api-keys.php' => config_path('api-keys.php'),
            ], 'api-keys-config');
        }
    }

    private function config(Application $app): ConfigRepository
    {
        return $app->make(ConfigRepository::class);
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
