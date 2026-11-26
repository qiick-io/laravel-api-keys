<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Per-key rate limit bucket. `bucketKey` MUST be derived from the record
 * id (and optionally IP) — never from request body / user input.
 */
final readonly class RateLimitDecision
{
    /** @internal The authenticator and eraser must name the same cache buckets. */
    public const string API_KEY_BUCKET_PREFIX = 'api-key:';

    /** @internal The rolling daily window. */
    public const string DAY_BUCKET_SUFFIX = ':day';

    /** @internal The rolling monthly window. */
    public const string MONTH_BUCKET_SUFFIX = ':month';

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
