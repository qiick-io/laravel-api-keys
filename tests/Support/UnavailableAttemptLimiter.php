<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Tests\Support;

use Qiick\ApiKeys\Contracts\AttemptLimiter;

/**
 * Test double: the attempt store is down (Redis or Memcached unreachable).
 */
final class UnavailableAttemptLimiter implements AttemptLimiter
{
    public function hit(string $key, int $decaySeconds = 60): int
    {
        throw new \RuntimeException('attempt store down');
    }

    public function decrement(string $key): void
    {
        throw new \RuntimeException('attempt store down');
    }

    public function availableIn(string $key): int
    {
        throw new \RuntimeException('attempt store down');
    }

    public function remaining(string $key, int $maxAttempts): int
    {
        throw new \RuntimeException('attempt store down');
    }
}
