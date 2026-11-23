<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Qiick\ApiKeys\Contracts\AttemptLimiter;

/**
 * @api Pre-auth brake for unknown/invalid tokens (design A15).
 *
 * Buckets IPv4 by full address (/32) and IPv6 by /64. IPv4-mapped IPv6
 * (::ffff:a.b.c.d) is expanded via {@see IpAllowlist::expandMapped} before
 * bucketing so dual-stack clients share the IPv4 bucket (not a single `v6:::`).
 * A null/empty/unparseable client IP does **not** share a bucket (that would
 * lock out everyone behind a misconfigured proxy): the brake is skipped.
 *
 * `maxPerMinute` ≤ 0 disables. Recipes should leave the default (20) on — see
 * README for NAT / shared-egress lockout risk.
 */
final class FailedAttemptLimiter
{
    private const int DECAY_SECONDS = 60;

    public function __construct(
        private AttemptLimiter $limiter,
        private int $maxPerMinute = 20,
        private IpAllowlist $ipAllowlist = new IpAllowlist,
    ) {}

    /**
     * Counts this attempt against the client's bucket before the token is
     * evaluated, and returns false when the bucket was already full.
     *
     * Counting first is what makes the cap hold under concurrency: guesses
     * racing from one network each take their own slot in one atomic
     * increment, so at most `maxPerMinute` of them are ever evaluated. A
     * refused attempt hands its slot back at once; the caller hands back the
     * slot of an attempt that turns out not to be a failure with
     * {@see release()}.
     */
    public function reserve(?string $clientIp): bool
    {
        $bucket = $this->enabledBucketKey($clientIp);

        if ($bucket === null) {
            return true;
        }

        if ($this->limiter->hit($bucket, self::DECAY_SECONDS) <= $this->maxPerMinute) {
            return true;
        }

        $this->limiter->decrement($bucket, self::DECAY_SECONDS);

        return false;
    }

    /**
     * Hands back a slot taken by {@see reserve()} for an attempt that was not
     * a failed guess (it authenticated, or was refused for another reason).
     */
    public function release(?string $clientIp): void
    {
        $bucket = $this->enabledBucketKey($clientIp);

        if ($bucket !== null) {
            $this->limiter->decrement($bucket, self::DECAY_SECONDS);
        }
    }

    public function availableIn(?string $clientIp): int
    {
        $bucket = $this->bucketKey($clientIp);
        if ($bucket === null) {
            return 0;
        }

        return $this->limiter->availableIn($bucket);
    }

    public function maxPerMinute(): int
    {
        return $this->maxPerMinute;
    }

    private function enabledBucketKey(?string $clientIp): ?string
    {
        if ($this->maxPerMinute <= 0) {
            return null;
        }

        return $this->bucketKey($clientIp);
    }

    /**
     * @internal Exposed for tests.
     */
    public function bucketKey(?string $clientIp): ?string
    {
        if ($clientIp === null || $clientIp === '') {
            return null;
        }

        $canonical = $this->ipAllowlist->expandMapped($clientIp);
        if ($canonical === null) {
            return null;
        }

        // expandMapped only returns addresses inet_pton already accepted.
        $binary = @inet_pton($canonical);
        if ($binary === false) {
            return null;
        }

        if (strlen($binary) === 4) {
            return 'api-key-failures:v4:'.$canonical;
        }

        // IPv6 /64: keep the first 64 bits, zero the rest.
        $network = substr($binary, 0, 8).str_repeat("\0", 8);
        $rendered = inet_ntop($network);
        // inet_ntop only fails on corrupt binary; our 16-byte network is always valid.
        if ($rendered === false) {
            return null;
        }

        return 'api-key-failures:v6:'.$rendered;
    }
}
