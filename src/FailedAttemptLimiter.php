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
 * Optional second tier: `maxPerMinutePerIpv6Slash48` (0, the default, is off) also caps failures across
 * a whole IPv6 /48, the usual size of a single allocation. Without it, an
 * attacker holding a /48 gets 65,536 separate /64 buckets.
 */
final class FailedAttemptLimiter
{
    public function __construct(
        private AttemptLimiter $limiter,
        private int $maxPerMinute = 20,
        private IpAllowlist $ipAllowlist = new IpAllowlist,
        // Equivalent mutant: any default <= 0 means the tier is off.
        private int $maxPerMinutePerIpv6Slash48 = 0, // @pest-mutate-ignore: DecrementInteger
    ) {}

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
        $bucket = $this->maxPerMinute > 0 ? $this->bucketKey($clientIp) : null;

        if ($bucket === null) {
            return [];
        }

        $limitsByBucketKey = [$bucket => $this->maxPerMinute];

        if ($this->maxPerMinutePerIpv6Slash48 > 0 && str_starts_with($bucket, 'api-key-failures:v6:')) {
            $limitsByBucketKey[$this->ipv6NetworkKey($clientIp, 6, 'v6-48')] = $this->maxPerMinutePerIpv6Slash48;
        }

        return $limitsByBucketKey;
    }

    /**
     * @internal Exposed for tests.
     */
    public function bucketKey(?string $clientIp): ?string
    {
        $canonical = $clientIp === null ? null : $this->ipAllowlist->expandMapped($clientIp);

        if ($canonical === null) {
            return null;
        }

        if (! str_contains($canonical, ':')) {
            return 'api-key-failures:v4:'.$canonical;
        }

        return $this->ipv6NetworkKey($canonical, 8, 'v6');
    }

    /**
     * Keeps the first `$networkBytes` bytes of an IPv6 address and zeroes the rest.
     */
    private function ipv6NetworkKey(?string $address, int $networkBytes, string $tier): string
    {
        // Equivalent mutants: bucketKey() already accepted this address, so it is set and inet_pton() succeeds.
        $binary = (string) inet_pton((string) $this->ipAllowlist->expandMapped((string) $address)); // @pest-mutate-ignore: RemoveStringCast
        $network = substr($binary, 0, $networkBytes).str_repeat("\0", 16 - $networkBytes);

        return 'api-key-failures:'.$tier.':'.inet_ntop($network);
    }
}
