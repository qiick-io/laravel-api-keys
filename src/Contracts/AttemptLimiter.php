<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

use Qiick\ApiKeys\CacheAttemptLimiter;

/**
 * @api Counter store behind the per-key rate limits and the pre-auth brake.
 *
 * The package never asks "is there room?" and then counts in a second step:
 * concurrent requests would all see room and all get through. It counts first
 * with {@see hit()}, which must be one atomic increment in the shared store,
 * and compares the returned count with the limit. An attempt that turns out
 * not to count (over the limit, or a successful key on the failure brake) is
 * handed back with {@see decrement()}.
 *
 * The package ships {@see CacheAttemptLimiter} (Redis,
 * Memcached) and binds it by default. Do not adapt Illuminate's `RateLimiter`:
 * its `increment()` recreates counters with a non-atomic `put()`, so parallel
 * requests overshoot the limit and counters go negative. Tests use the
 * in-memory fake.
 */
interface AttemptLimiter
{
    /**
     * Atomically adds one attempt to `$key` and returns the bucket's count
     * including it. The first hit opens a window of `$decaySeconds`; later
     * hits must not extend it.
     */
    public function hit(string $key, int $decaySeconds = 60): int;

    /**
     * Atomically takes back one attempt previously added with {@see hit()}.
     * A missing counter (its window expired) stays missing, and a counter
     * never goes below zero.
     */
    public function decrement(string $key): void;

    public function availableIn(string $key): int;

    public function remaining(string $key, int $maxAttempts): int;
}
