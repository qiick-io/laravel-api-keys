<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Cache\Repository;
use Qiick\ApiKeys\Contracts\AttemptLimiter;

/**
 * @api {@see AttemptLimiter} on Laravel's own {@see RateLimiter}, over whichever
 * cache store the product picks (`api-keys.cache_store`, default store when null).
 *
 * The authenticator counts first and compares the returned count with the
 * limit, so the guarantee is only as strong as the store's `increment()`:
 *
 * - Redis, Memcached, DynamoDB, and the database store on MySQL or PostgreSQL
 *   increment atomically across workers.
 * - The file store reads, adds and writes back without a lock: parallel workers,
 *   even on one server, can let more attempts through than the limit.
 *   `api-keys:check` warns about it.
 * - The array store keeps counters per process: tests only.
 *
 * One small race is accepted by design (docs/security.md): when a window
 * renews, Laravel resets the counter with a `put()`, so attempts that arrive
 * at that exact instant can each read 1. For a brake on high-entropy keys this
 * lets a handful of extra guesses through per window, never an unbounded number.
 */
final class CacheAttemptLimiter implements AttemptLimiter
{
    private RateLimiter $rateLimiter;

    public function __construct(
        private Repository $cache,
    ) {
        $this->rateLimiter = new RateLimiter($cache);
    }

    /**
     * @throws \InvalidArgumentException when the window is shorter than one second:
     *                                   the counter would expire at once and open the limit
     * @throws \RuntimeException when the store did not count the attempt; the authenticator answers 503
     */
    public function hit(string $key, int $decaySeconds = 60): int
    {
        if ($decaySeconds < 1) {
            throw new \InvalidArgumentException('An attempt window must last at least one second.');
        }

        $hits = $this->rateLimiter->hit($key, $decaySeconds);

        // A store that failed to count (an unreachable Memcached, the null store) makes
        // Laravel cast `false` to 0, which is under every limit: fail closed instead.
        return $hits >= 1 ? $hits : throw new \RuntimeException('The cache store did not count the attempt.');
    }

    /**
     * Only a live counter above zero is taken back, through the cache's own
     * `decrement()`: `RateLimiter::decrement()` is an `increment()` by -1, which
     * Memcached refuses (a negative offset).
     *
     * The counter can still expire between the check and the decrement. Redis,
     * the file and the array store then create it at -1 with no expiry, and every
     * later hit would count 0 and fail closed for good. Putting it back to 0 lets
     * the next hit count 1, which Laravel's `RateLimiter` stores with a fresh window.
     */
    public function decrement(string $key): void
    {
        if ($this->rateLimiter->attempts($key) <= 0) {
            return;
        }

        $cleanKey = $this->rateLimiter->cleanRateLimiterKey($key);

        if ($this->cache->decrement($cleanKey) < 0) {
            $this->cache->increment($cleanKey);
        }
    }

    public function availableIn(string $key): int
    {
        return $this->rateLimiter->availableIn($key);
    }

    public function remaining(string $key, int $maxAttempts): int
    {
        return $this->rateLimiter->remaining($key, $maxAttempts);
    }
}
