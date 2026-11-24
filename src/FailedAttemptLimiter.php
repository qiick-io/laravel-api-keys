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
    public function __construct(
        private AttemptLimiter $limiter,
        private int $maxPerMinute = 20,
        private IpAllowlist $ipAllowlist = new IpAllowlist,
    ) {}

    /**
     * True once the client's bucket holds `maxPerMinute` failed guesses. Only
     * reads the counter: a request that is still being verified takes no slot.
     */
    public function isBlocked(?string $clientIp): bool
    {
        $bucket = $this->enabledBucketKey($clientIp);

        return $bucket !== null && $this->limiter->remaining($bucket, $this->maxPerMinute) === 0;
    }

    /**
     * Counts a failed guess with one atomic increment and returns false when it
     * went over the limit; the caller then answers `rate_limited` instead of
     * `invalid_token`, so guesses past the limit teach an attacker nothing
     * even when they race.
     */
    public function countFailure(?string $clientIp): bool
    {
        $bucket = $this->enabledBucketKey($clientIp);

        return $bucket === null || $this->limiter->hit($bucket, 60) <= $this->maxPerMinute;
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
        if ($clientIp === null || $clientIp === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty
            return null;
        }

        $canonical = $this->ipAllowlist->expandMapped($clientIp);
        if ($canonical === null) {
            return null;
        }

        // expandMapped only returns addresses inet_pton already accepted.
        $binary = @inet_pton($canonical);
        if ($binary === false) { // @pest-mutate-ignore: FalseToTrue
            return null; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        if (strlen($binary) === 4) {
            return 'api-key-failures:v4:'.$canonical;
        }

        // IPv6 /64: keep the first 64 bits, zero the rest.
        $network = substr($binary, 0, 8).str_repeat("\0", 8);
        $rendered = inet_ntop($network);
        // inet_ntop only fails on corrupt binary; our 16-byte network is always valid.
        if ($rendered === false) { // @pest-mutate-ignore: FalseToTrue
            return null; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        return 'api-key-failures:v6:'.$rendered;
    }
}
