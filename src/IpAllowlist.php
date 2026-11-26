<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Symfony\Component\HttpFoundation\IpUtils;

/**
 * @api IP allowlist check with IpUtils + normalisation.
 *
 * - null / [] → allow all
 * - present but not a list of strings → deny
 * - zone-id in the client IP (fe80::1%eth0) → not allowed
 * - IPv4-mapped addresses (::ffff:a.b.c.d / ::ffff:0:0/96) expand to dotted IPv4
 * - IPv4-compatible (::a.b.c.d) are NOT unwrapped (deprecated; ::1 and :: stay IPv6)
 * - Mapped CIDR: prefix ≥ 96 → IPv4 with prefix−96; prefix < 96 → malformed deny
 * - Prefix out of range for the family (IPv4 0–32, IPv6 0–128), or written with
 *   a leading zero (`/00`, `/024`) → deny
 */
final class IpAllowlist
{
    private const string MAPPED_PREFIX = "\0\0\0\0\0\0\0\0\0\0\xff\xff";

    public function allows(?string $ip, mixed $allowlist): bool
    {
        if ($allowlist === null || $allowlist === []) {
            return true;
        }

        if (! is_array($allowlist) || ! array_is_list($allowlist)) {
            return false;
        }

        $entries = [];
        foreach ($allowlist as $entry) {
            $expanded = $this->expandedEntry($entry);
            if ($expanded === null) {
                return false;
            }
            $entries[] = $expanded;
        }

        // An unknown client cannot be inside a non-empty allowlist.
        if ($ip === null || str_contains($ip, '%')) {
            return false;
        }

        $client = $this->expandMapped($ip);
        if ($client === null) {
            return false;
        }

        return IpUtils::checkIp($client, $entries);
    }

    /**
     * Whether one allowlist entry is valid, by the same rules {@see allows()}
     * applies: an IPv4 or IPv6 address or CIDR, no zone id, a prefix in range
     * for the family, and IPv4-mapped CIDR only from /96. Forms validate input
     * with it instead of probing allows().
     */
    public function isValidEntry(mixed $entry): bool
    {
        return $this->expandedEntry($entry) !== null;
    }

    /**
     * The entry in the form IpUtils matches, or null when it is not valid.
     */
    private function expandedEntry(mixed $entry): ?string
    {
        if (! is_string($entry) || str_contains($entry, '%')) {
            return null;
        }

        return $this->expandMappedEntry($entry);
    }

    /**
     * Unwrap IPv4-mapped addresses (::ffff:a.b.c.d) to dotted IPv4; leave other
     * forms as inet_ntop. Shared by {@see FailedAttemptLimiter} so mapped clients
     * bucket with IPv4 peers instead of collapsing onto `v6:::`.
     */
    public function expandMapped(string $ip): ?string
    {
        $binary = $this->packed($ip);

        // inet_ntop() only fails on a malformed binary, and packed() never returns one.
        return $binary === null ? null : (inet_ntop($binary) ?: null);
    }

    /**
     * The address in network byte order: 4 bytes for IPv4 (IPv4-mapped IPv6
     * unwrapped), 16 for IPv6; null when it does not parse.
     */
    public function packed(string $ip): ?string
    {
        $binary = @inet_pton($ip);

        if ($binary === false) {
            return null;
        }

        return strlen($binary) === 16 && str_starts_with($binary, self::MAPPED_PREFIX)
            ? substr($binary, 12)
            : $binary;
    }

    private function isIpv4Mapped(string $ip): bool
    {
        $binary = @inet_pton($ip);

        return $binary !== false
            && strlen($binary) === 16
            && str_starts_with($binary, self::MAPPED_PREFIX);
    }

    private function expandMappedEntry(string $entry): ?string
    {
        if (! str_contains($entry, '/')) {
            return $this->expandMapped($entry);
        }

        $parts = explode('/', $entry);
        // Digits without a leading zero: "/00" or "/024" would read as /0 or /24, and a typo
        // must never turn into the match-all /0.
        if (count($parts) !== 2 || preg_match('/^(0|[1-9][0-9]*)$/D', $parts[1]) !== 1) {
            return null;
        }

        $address = $parts[0];
        $prefixLength = (int) $parts[1];
        $wasMapped = $this->isIpv4Mapped($address);
        $expanded = $this->expandMapped($address);
        if ($expanded === null) {
            return null;
        }

        if ($wasMapped) {
            // Mapped CIDR uses an IPv6-length prefix; only ≥ 96 maps onto IPv4.
            if ($prefixLength < 96) {
                return null;
            }
            $prefixLength -= 96;
        }

        $maxPrefix = str_contains($expanded, ':') ? 128 : 32;
        if ($prefixLength > $maxPrefix) {
            return null;
        }

        return $expanded.'/'.$prefixLength;
    }
}
