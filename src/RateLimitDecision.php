<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Per-key rate limit bucket. `bucketKey` MUST be derived from the record
 * id (and optionally IP) — never from request body / user input.
 */
final readonly class RateLimitDecision
{
    /**
     * @throws \InvalidArgumentException when the window is shorter than one second
     */
    public function __construct(
        public string $bucketKey,
        public int $maxAttempts,
        public int $decaySeconds = 60,
    ) {
        // A zero or negative window expires the counter at once and silently opens the limit.
        if ($decaySeconds < 1) {
            throw new \InvalidArgumentException('RateLimitDecision decaySeconds must be at least 1.');
        }
    }
}
