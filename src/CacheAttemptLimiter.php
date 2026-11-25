<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Illuminate\Cache\RateLimiter;
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
    public function __construct(
        private RateLimiter $rateLimiter,
    ) {}

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
     * Only a live counter above zero is taken back. Laravel's `decrement()` is an
     * `increment()` by -1, so on an expired counter it would create one at -1
     * with a fresh 60-second window, cutting a day or month bucket short.
     */
    public function decrement(string $key): void
    {
        if ($this->rateLimiter->attempts($key) > 0) {
            $this->rateLimiter->decrement($key);
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
