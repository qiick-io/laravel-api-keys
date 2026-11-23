<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Tests\Support;

use Closure;
use Qiick\ApiKeys\Contracts\AttemptLimiter;
use Qiick\ApiKeys\Testing\FakeAttemptLimiter;

/**
 * Test double that simulates two concurrent requests in one PHP process.
 *
 * The first limiter call computes its answer against the shared counter, then
 * runs the injected "second request" before returning that answer. That is the
 * exact interleaving two workers hitting one cache produce, so a limiter
 * protocol that is not a single atomic step lets both requests through.
 */
final class InterleavingAttemptLimiter implements AttemptLimiter
{
    private ?Closure $concurrentRequest = null;

    public function __construct(
        public readonly FakeAttemptLimiter $inner = new FakeAttemptLimiter,
    ) {}

    public function interleave(Closure $concurrentRequest): void
    {
        $this->concurrentRequest = $concurrentRequest;
    }

    public function tooManyAttempts(string $key, int $maxAttempts): bool
    {
        $answer = $this->inner->tooManyAttempts($key, $maxAttempts);
        $this->runConcurrentRequestOnce();

        return $answer;
    }

    public function hit(string $key, int $decaySeconds = 60): void
    {
        $this->inner->hit($key, $decaySeconds);
        $this->runConcurrentRequestOnce();
    }

    public function availableIn(string $key): int
    {
        return $this->inner->availableIn($key);
    }

    public function remaining(string $key, int $maxAttempts): int
    {
        return $this->inner->remaining($key, $maxAttempts);
    }

    private function runConcurrentRequestOnce(): void
    {
        $concurrentRequest = $this->concurrentRequest;
        $this->concurrentRequest = null;

        if ($concurrentRequest !== null) {
            $concurrentRequest();
        }
    }
}
