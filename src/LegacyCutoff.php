<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @internal Parses `api-keys.legacy.accept_until`, the hard end of legacy token acceptance.
 *
 * One parser for boot validation and for `api-keys:notify-expiring`, so both read
 * the same instant. Only absolute timestamps are accepted: `DATE_ATOM` with an
 * offset, or UTC `Z`. Relative strings (`now`, `+10 years`) and date-only values
 * would move or blur the cut-off, so they are refused.
 */
final class LegacyCutoff
{
    /**
     * @return \DateTimeImmutable|null null when unset (null or empty)
     *
     * @throws \RuntimeException when set to anything but an absolute timestamp
     */
    public static function parse(mixed $configured): ?\DateTimeImmutable
    {
        if ($configured === null || $configured === '') {
            return null;
        }

        $atom = is_string($configured) && str_ends_with($configured, 'Z')
            ? substr($configured, 0, -1).'+00:00'
            : $configured;

        $parsed = is_string($atom) ? \DateTimeImmutable::createFromFormat(\DateTimeInterface::ATOM, $atom) : false;

        // The round trip refuses overflowing dates (2027-02-30) that createFromFormat would roll over.
        if ($parsed === false || $parsed->format(\DateTimeInterface::ATOM) !== $atom) {
            throw new \RuntimeException(
                'api-keys.legacy.accept_until (API_KEYS_LEGACY_ACCEPT_UNTIL) must be an absolute ISO-8601 timestamp with offset (DATE_ATOM) or UTC Z, e.g. 2027-01-01T00:00:00Z or 2027-01-01T00:00:00+00:00.',
            );
        }

        return $parsed;
    }
}
