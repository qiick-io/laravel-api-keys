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
 * - Prefix out of range for the family (IPv4 0–32, IPv6 0–128) → deny
 */
final class IpAllowlist
{
    private const string MAPPED_PREFIX = "\0\0\0\0\0\0\0\0\0\0\xff\xff";

    public function allows(string $ip, mixed $allowlist): bool
    {
        if ($allowlist === null || $allowlist === []) {
            return true;
        }

        if (! is_array($allowlist) || ! array_is_list($allowlist)) {
            return false;
        }

        foreach ($allowlist as $entry) {
            if (! is_string($entry) || str_contains($entry, '%')) {
                return false;
            }
        }

        if (str_contains($ip, '%')) {
            return false;
        }

        $client = $this->expandMapped($ip);
        if ($client === null) {
            return false;
        }

        $entries = [];
        foreach ($allowlist as $entry) {
            $expanded = $this->expandMappedEntry($entry);
            if ($expanded === null) {
                return false;
            }
            $entries[] = $expanded;
        }

        return IpUtils::checkIp($client, $entries);
    }

    /**
     * Unwrap IPv4-mapped addresses to dotted IPv4 only. ::1 / :: stay IPv6.
     */
    private function expandMapped(string $ip): ?string
    {
        $binary = @inet_pton($ip);
        if ($binary === false) {
            return null;
        }

        if (strlen($binary) === 16 && str_starts_with($binary, self::MAPPED_PREFIX)) {
            // inet_ntop cannot fail for a 4-byte slice from a successful inet_pton.
            return (string) inet_ntop(substr($binary, 12)); // @pest-mutate-ignore
        }

        // inet_ntop cannot fail for a binary from a successful inet_pton.
        return (string) inet_ntop($binary); // @pest-mutate-ignore
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
        if (count($parts) !== 2 || ! ctype_digit($parts[1])) {
            return null;
        }

        $address = $parts[0];
        $prefixLength = (int) $parts[1]; // @pest-mutate-ignore RemoveIntegerCast — ctype_digit already; cast is for typed arithmetic
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
