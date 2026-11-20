<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\Contracts\AttemptLimiter;

/**
 * @api In-memory attempt brake for authenticator tests.
 */
final class FakeAttemptLimiter implements AttemptLimiter
{
    /** @var array<string, int> */
    private array $hits = [];

    /** @var array<string, int> */
    private array $availableIn = [];

    /** @var array<string, int> */
    public array $lastDecaySeconds = [];

    public function tooManyAttempts(string $key, int $maxAttempts): bool
    {
        return ($this->hits[$key] ?? 0) >= $maxAttempts;
    }

    public function hit(string $key, int $decaySeconds = 60): void
    {
        $this->hits[$key] = ($this->hits[$key] ?? 0) + 1;
        $this->availableIn[$key] = $decaySeconds;
        $this->lastDecaySeconds[$key] = $decaySeconds;
    }

    public function availableIn(string $key): int
    {
        return $this->availableIn[$key] ?? 0;
    }

    public function remaining(string $key, int $maxAttempts): int
    {
        return max(0, $maxAttempts - ($this->hits[$key] ?? 0));
    }

    public function hitsFor(string $key): int
    {
        return $this->hits[$key] ?? 0;
    }
}
