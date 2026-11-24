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
 *
 * Optional second tier: `maxPerMinutePerIpv6Slash48` (null, the default, is
 * off; otherwise at least 1) also caps failures across a whole IPv6 /48, the usual size of a single allocation. Without it, an
 * attacker holding a /48 gets 65,536 separate /64 buckets.
 */
final class FailedAttemptLimiter
{
    /**
     * @throws \InvalidArgumentException when the /48 limit is below one (leave it null to turn the tier off)
     */
    public function __construct(
        private AttemptLimiter $limiter,
        private int $maxPerMinute = 20,
        private IpAllowlist $ipAllowlist = new IpAllowlist,
        private ?int $maxPerMinutePerIpv6Slash48 = null,
    ) {
        if ($maxPerMinutePerIpv6Slash48 !== null && $maxPerMinutePerIpv6Slash48 < 1) {
            throw new \InvalidArgumentException('maxPerMinutePerIpv6Slash48 must be at least 1, or null to turn the /48 tier off.');
        }
    }

    /**
     * True once any of the client's buckets holds its limit of failed guesses.
     * Only reads the counters: a request still being verified takes no slot.
     */
    public function isBlocked(?string $clientIp): bool
    {
        foreach ($this->limitsByBucketKey($clientIp) as $bucket => $maxAttempts) {
            if ($this->limiter->remaining($bucket, $maxAttempts) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Counts a failed guess in every bucket of the client with one atomic
     * increment each, and returns false when any went over its limit; the
     * caller then answers `rate_limited` instead of `invalid_token`, so
     * guesses past the limit teach an attacker nothing even when they race.
     */
    public function countFailure(?string $clientIp): bool
    {
        $isWithinLimits = true;

        foreach ($this->limitsByBucketKey($clientIp) as $bucket => $maxAttempts) {
            // Every tier counts, even once another tier is over.
            $isWithinLimits = $this->limiter->hit($bucket, 60) <= $maxAttempts && $isWithinLimits;
        }

        return $isWithinLimits;
    }

    public function availableIn(?string $clientIp): int
    {
        $secondsLeft = 0;

        foreach (array_keys($this->limitsByBucketKey($clientIp)) as $bucket) {
            $secondsLeft = max($secondsLeft, $this->limiter->availableIn($bucket));
        }

        return $secondsLeft;
    }

    public function maxPerMinute(): int
    {
        return $this->maxPerMinute;
    }

    /**
     * @return array<string, int> the limit of each bucket that applies to the client
     */
    private function limitsByBucketKey(?string $clientIp): array
    {
        $binary = $this->maxPerMinute > 0 ? $this->packedClientIp($clientIp) : null;

        if ($binary === null) {
            return [];
        }

        $limitsByBucketKey = [$this->bucketKeyFor($binary) => $this->maxPerMinute];

        if ($this->maxPerMinutePerIpv6Slash48 !== null && strlen($binary) === 16) {
            $limitsByBucketKey[$this->networkKey($binary, 6, 'v6-48')] = $this->maxPerMinutePerIpv6Slash48;
        }

        return $limitsByBucketKey;
    }

    /**
     * @internal Exposed for tests.
     */
    public function bucketKey(?string $clientIp): ?string
    {
        $binary = $this->packedClientIp($clientIp);

        return $binary === null ? null : $this->bucketKeyFor($binary);
    }

    private function packedClientIp(?string $clientIp): ?string
    {
        return $clientIp === null ? null : $this->ipAllowlist->packed($clientIp);
    }

    /**
     * IPv4 by full address, IPv6 by /64.
     */
    private function bucketKeyFor(string $binary): string
    {
        return strlen($binary) === 4 ? $this->networkKey($binary, 4, 'v4') : $this->networkKey($binary, 8, 'v6');
    }

    /**
     * Keeps the first `$networkBytes` bytes of the address and zeroes the rest.
     */
    private function networkKey(string $binary, int $networkBytes, string $tier): string
    {
        $network = substr($binary, 0, $networkBytes).str_repeat("\0", strlen($binary) - $networkBytes);

        return 'api-key-failures:'.$tier.':'.inet_ntop($network);
    }
}
