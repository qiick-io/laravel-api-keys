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
 * - IPv4-mapped / IPv4-compatible addresses are expanded to dotted IPv4 before
 *   IpUtils::checkIp; malformed entries deny
 */
final class IpAllowlist
{
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
     * Expand IPv4-mapped/compatible addresses to dotted IPv4; otherwise return
     * the address unchanged when parseable, else null.
     */
    private function expandMapped(string $ip): ?string
    {
        $binary = @inet_pton($ip);
        if ($binary === false) {
            return null;
        }

        if (strlen($binary) === 16) {
            $mappedPrefix = "\0\0\0\0\0\0\0\0\0\0\xff\xff";
            $compatiblePrefix = "\0\0\0\0\0\0\0\0\0\0\0\0";
            if (str_starts_with($binary, $mappedPrefix) || str_starts_with($binary, $compatiblePrefix)) {
                // inet_ntop cannot fail for a 4-byte slice from a successful inet_pton.
                return (string) inet_ntop(substr($binary, 12)); // @pest-mutate-ignore
            }
        }

        // inet_ntop cannot fail for a binary from a successful inet_pton.
        return (string) inet_ntop($binary); // @pest-mutate-ignore
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

        $expanded = $this->expandMapped($parts[0]);
        if ($expanded === null) {
            return null;
        }

        return $expanded.'/'.$parts[1];
    }
}
