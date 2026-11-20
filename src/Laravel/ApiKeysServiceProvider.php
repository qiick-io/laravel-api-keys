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

            $legacyAcceptUntil = $this->validatedLegacyAcceptUntil($app);

            return new TokenCodec(
                productPrefix: $productPrefix,
                environment: $app->make(EnvironmentResolver::class),
                random: $app->make(RandomSource::class),
                legacyMatchers: $this->resolveLegacyMatchers($app, $legacyMatchers),
                legacyAcceptUntil: $legacyAcceptUntil,
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
        $this->validatedLegacyAcceptUntil();

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

        $acceptUntil = $this->config($application)->get('api-keys.legacy.accept_until');

        if ($acceptUntil === null || $acceptUntil === '') {
            if ($legacyMatchers !== []) {
                throw new \RuntimeException(
                    'api-keys.legacy.accept_until (API_KEYS_LEGACY_ACCEPT_UNTIL) is required when legacy_matchers is non-empty.'
                );
            }

            return null;
        }

        if (! is_string($acceptUntil)) {
            throw $this->invalidLegacyAcceptUntilException();
        }

        return $this->parseAbsoluteAcceptUntil($acceptUntil);
    }

    /**
     * Absolute ISO-8601 with offset ({@see \DateTimeInterface::ATOM}) or UTC "Z".
     * Relative strings (`now`, `tomorrow`, `+10 years`) and date-only values are rejected.
     */
    private function parseAbsoluteAcceptUntil(string $acceptUntil): \DateTimeImmutable
    {
        $parsed = $this->parseAbsoluteAcceptUntilFormat($acceptUntil, \DateTimeInterface::ATOM);
        if ($parsed instanceof \DateTimeImmutable) {
            return $parsed;
        }

        if (str_ends_with($acceptUntil, 'Z')) {
            $normalized = substr($acceptUntil, 0, -1).'+00:00';
            $parsedZulu = $this->parseAbsoluteAcceptUntilFormat($normalized, \DateTimeInterface::ATOM);
            if ($parsedZulu instanceof \DateTimeImmutable) {
                return $parsedZulu;
            }
        }

        throw $this->invalidLegacyAcceptUntilException();
    }

    private function parseAbsoluteAcceptUntilFormat(string $acceptUntil, string $format): ?\DateTimeImmutable
    {
        $parsed = \DateTimeImmutable::createFromFormat($format, $acceptUntil);
        $errors = \DateTimeImmutable::getLastErrors();
        $hasErrors = is_array($errors)
            && (($errors['warning_count'] ?? 0) > 0 || ($errors['error_count'] ?? 0) > 0);

        if ($parsed === false || $hasErrors || $parsed->format($format) !== $acceptUntil) {
            return null;
        }

        return $parsed;
    }

    private function invalidLegacyAcceptUntilException(): \RuntimeException
    {
        return new \RuntimeException(
            'api-keys.legacy.accept_until (API_KEYS_LEGACY_ACCEPT_UNTIL) must be an absolute ISO-8601 timestamp with offset (DATE_ATOM) or UTC Z, e.g. 2027-01-01T00:00:00Z or 2027-01-01T00:00:00+00:00.',
        );
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
