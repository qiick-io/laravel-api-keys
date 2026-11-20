<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Qiick\ApiKeys\Contracts\AttemptLimiter;

/**
 * @api Pre-auth per-IP brake for unknown/invalid tokens (design A15).
 *
 * `maxPerMinute` ≤ 0 disables. Recipes should leave the default (20) on.
 */
final class FailedAttemptLimiter
{
    public function __construct(
        private AttemptLimiter $limiter,
        private int $maxPerMinute = 20,
    ) {}

    public function tooManyAttempts(string $clientIp): bool
    {
        if ($this->maxPerMinute <= 0) {
            return false;
        }

        return $this->limiter->tooManyAttempts($this->bucketKey($clientIp), $this->maxPerMinute);
    }

    public function hit(string $clientIp): void
    {
        if ($this->maxPerMinute <= 0) {
            return;
        }

        $this->limiter->hit($this->bucketKey($clientIp), 60);
    }

    public function availableIn(string $clientIp): int
    {
        return $this->limiter->availableIn($this->bucketKey($clientIp));
    }

    public function maxPerMinute(): int
    {
        return $this->maxPerMinute;
    }

    private function bucketKey(string $clientIp): string
    {
        return 'api-key-failures:'.$clientIp;
    }
}
