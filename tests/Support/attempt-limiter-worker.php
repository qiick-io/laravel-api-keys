<?php

declare(strict_types=1);

/**
 * One "request" of the real-store concurrency test, run as its own PHP process
 * so that parallel workers race on the shared cache exactly like PHP-FPM
 * workers do. Prints 1 when the attempt was admitted, 0 when refused.
 *
 * Usage: php attempt-limiter-worker.php <redis|memcached> <operation> <ip-or-key> <max> <start-at>
 * Operations on the failed-attempt brake for an IP: guess (a failed guess) and
 * request / slow-request (a key that authenticates).
 * Operations on a raw counter key: hit (give the attempt back when over max),
 * hit-short (hit with a one-second window), decrement, forget, and count
 * (prints the stored value, or "missing").
 */

use Illuminate\Cache\MemcachedConnector;
use Illuminate\Cache\MemcachedStore;
use Illuminate\Cache\RedisStore;
use Illuminate\Cache\Repository;
use Illuminate\Container\Container;
use Illuminate\Redis\RedisManager;
use Qiick\ApiKeys\CacheAttemptLimiter;
use Qiick\ApiKeys\FailedAttemptLimiter;

require __DIR__.'/../../vendor/autoload.php';

[, $storeName, $operation, $key, $maxAttempts, $startAt] = $argv;

$store = match ($storeName) {
    'redis' => new RedisStore(
        new RedisManager(new Container, 'phpredis', [
            'default' => [
                'host' => getenv('API_KEYS_REDIS_HOST') ?: '127.0.0.1',
                'port' => (int) (getenv('API_KEYS_REDIS_PORT') ?: 6379),
                'database' => 15,
            ],
        ]),
        'api-keys-limiter-test:',
    ),
    'memcached' => new MemcachedStore(
        (new MemcachedConnector)->connect([[
            'host' => getenv('API_KEYS_MEMCACHED_HOST') ?: '127.0.0.1',
            'port' => (int) (getenv('API_KEYS_MEMCACHED_PORT') ?: 11211),
            'weight' => 100,
        ]]),
        'api-keys-limiter-test:',
    ),
    default => throw new InvalidArgumentException('Unknown store '.$storeName),
};

$limiter = new CacheAttemptLimiter(new Repository($store));

// Start together: every worker waits for the same instant before touching the store.
if ((float) $startAt > microtime(true)) {
    time_sleep_until((float) $startAt);
}

$maxAttempts = (int) $maxAttempts;

echo match ($operation) {
    // A failed guess, as ApiKeyAuthenticator handles it: refused early when the bucket is full, else counted.
    'guess' => (function () use ($limiter, $maxAttempts, $key): int {
        $brake = new FailedAttemptLimiter($limiter, $maxAttempts);

        return ! $brake->isBlocked($key) && $brake->countFailure($key) ? 1 : 0;
    })(),
    // A valid key whose verification (lookup, hash, authorizer) takes 0 or 200 ms; it is only read against the brake.
    'request', 'slow-request' => (function () use ($limiter, $maxAttempts, $key, $operation): int {
        $brake = new FailedAttemptLimiter($limiter, $maxAttempts);

        if ($brake->isBlocked($key)) {
            return 0;
        }

        usleep($operation === 'slow-request' ? 200_000 : 0);

        return $brake->isBlocked($key) ? 0 : 1;
    })(),
    'hit' => (function () use ($limiter, $maxAttempts, $key): int {
        if ($limiter->hit($key, 60) <= $maxAttempts) {
            return 1;
        }

        $limiter->decrement($key);

        return 0;
    })(),
    'hit-short' => $limiter->hit($key, 1),
    'decrement' => (function () use ($limiter, $key): int {
        $limiter->decrement($key);

        return 0;
    })(),
    'forget' => (int) $store->forget($key) & (int) $store->forget($key.':timer'),
    'count' => is_numeric($counter = $store->get($key)) ? (string) (int) $counter : 'missing',
    default => throw new InvalidArgumentException('Unknown operation '.$operation),
};
