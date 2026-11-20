<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Per-key rate limit bucket. `bucketKey` MUST be derived from the record
 * id (and optionally IP) — never from request body / user input.
 */
final readonly class RateLimitDecision
{
    public function __construct(
        public string $bucketKey,
        public int $maxAttempts,
        public int $decaySeconds = 60,
    ) {}
}
