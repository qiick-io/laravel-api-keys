<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

/**
 * @api Brake for per-key (and later pre-auth) attempt buckets.
 *
 * Products typically adapt Illuminate's RateLimiter; tests use an in-memory fake.
 */
interface AttemptLimiter
{
    public function tooManyAttempts(string $key, int $maxAttempts): bool;

    public function hit(string $key, int $decaySeconds = 60): void;

    public function availableIn(string $key): int;

    public function remaining(string $key, int $maxAttempts): int;
}
