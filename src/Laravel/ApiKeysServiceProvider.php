<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Laravel;

use Illuminate\Support\ServiceProvider;

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
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../../config/api-keys.php' => config_path('api-keys.php'),
            ], 'api-keys-config');
        }
    }
}
