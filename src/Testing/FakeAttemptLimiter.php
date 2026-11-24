<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\Contracts\AttemptLimiter;

/**
 * @api In-memory attempt brake for authenticator tests.
 */
final class FakeAttemptLimiter implements AttemptLimiter
{
    use EnsuresTestingEnvironmentTrait;

    /** @var array<string, int> */
    private array $hits = [];

    /** @var array<string, int> */
    private array $availableIn = [];

    /** @var array<string, int> */
    public array $lastDecaySeconds = [];

    public function __construct()
    {
        self::ensureTestingEnvironment();
    }

    public function hit(string $key, int $decaySeconds = 60): int
    {
        $this->hits[$key] = ($this->hits[$key] ?? 0) + 1;
        $this->availableIn[$key] = $decaySeconds;
        $this->lastDecaySeconds[$key] = $decaySeconds;

        return $this->hits[$key];
    }

    public function decrement(string $key, int $decaySeconds = 60): void
    {
        $this->hits[$key] = ($this->hits[$key] ?? 0) - 1;
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
