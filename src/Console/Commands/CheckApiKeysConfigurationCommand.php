<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Console\Commands;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\FileStore;
use Illuminate\Cache\NullStore;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use Qiick\ApiKeys\CacheAttemptLimiter;
use Qiick\ApiKeys\Contracts\AttemptLimiter;
use Qiick\ApiKeys\Laravel\ApiKeysServiceProvider;
use Qiick\ApiKeys\TokenCodec;

/**
 * @api Deploy-time check: `php artisan api-keys:check` fails (exit 1) when the
 * package cannot work as configured.
 *
 * It re-validates the settings, checks that `app.timezone` is UTC, builds the
 * {@see TokenCodec} (product prefix, token version, environment), and resolves the bound {@see AttemptLimiter}
 * and prints which one is active. It fails on the null cache store (no
 * counters at all) and warns on the file store (not atomic across workers) and
 * on the array store outside tests. Boot deliberately skips the store so
 * artisan keeps working; run this command in the deploy pipeline.
 */
final class CheckApiKeysConfigurationCommand extends Command
{
    protected $signature = 'api-keys:check';

    protected $description = 'Check that the API keys package can run with this configuration';

    public function handle(): int
    {
        try {
            // This provider registers the command, so it is always loaded here.
            /** @var ApiKeysServiceProvider $provider */
            $provider = $this->laravel->getProvider(ApiKeysServiceProvider::class);
            $provider->validateConfiguration();

            $this->line('Attempt limiter: '.$this->describeAttemptLimiter($this->laravel->make(AttemptLimiter::class)));
            // Builds the environment resolver too: product prefix, token version and environment.
            $this->laravel->make(TokenCodec::class);

            // Expiry, grace and lease comparisons assume UTC timestamps (RFC 3339 on the wire).
            if (config('app.timezone') !== 'UTC') {
                throw new \RuntimeException('app.timezone must be UTC: API key timestamps are stored and compared in UTC.');
            }
        } catch (\InvalidArgumentException|\RuntimeException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $this->info('API keys configuration is ready.');

        return self::SUCCESS;
    }

    /**
     * Names the active limiter and judges its store. Only a store that keeps no
     * counters at all fails; the others are the product's choice and get a
     * warning when they cannot hold the limits across workers.
     *
     * @throws \RuntimeException on the null store: the limits and the brake would be off
     */
    private function describeAttemptLimiter(AttemptLimiter $limiter): string
    {
        if (! $limiter instanceof CacheAttemptLimiter) {
            return $limiter::class.' (bound by the application).';
        }

        // Boot already validated api-keys.cache_store: a store name, or null for the default.
        $configuredStore = config('api-keys.cache_store');
        $storeName = is_string($configuredStore) ? $configuredStore : config()->string('cache.default');
        $store = Cache::store($storeName)->getStore();

        if ($store instanceof NullStore) {
            throw new \RuntimeException('The null cache store keeps no attempt counters: the rate limits and the failed-attempt brake would be off. Set api-keys.cache_store to a real store.');
        }

        if ($store instanceof FileStore) {
            $this->warn('The file cache store does not increment atomically: parallel workers can let more attempts through than the limits. In production use redis, memcached, dynamodb, or database on MySQL/PostgreSQL.');
        }

        if ($store instanceof ArrayStore && ! $this->laravel->environment('testing')) {
            $this->warn('The array cache store keeps attempt counters per process: the limits do not hold across requests outside tests.');
        }

        return "Laravel RateLimiter on the {$storeName} cache store.";
    }
}
