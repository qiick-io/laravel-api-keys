<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Portable SQL for the expiry-notice claim lease (products / engine smoke).
 *
 * Claim sets `expiry_notice_claimed_at` and `expiry_notice_claim_token` only
 * when the notice is still unsent, the row still has the `expires_at` the
 * command selected, and it is either unclaimed or the prior claim is older than
 * the lease. Mark and release apply only while the row holds that same token
 * and `expires_at`: a run whose lease expired cannot touch the next run's claim,
 * and a rotation in between is never stamped as notified.
 *
 * `expires_at` is matched within {@see expiryWindow()}, not by equality, so a
 * product that keeps more or less sub-second precision than the column (MySQL
 * `DATETIME` truncates or rounds fractions) still matches. Bind both bounds like
 * every other timestamp of the column: the same layout and, for
 * `TIMESTAMPTZ`, an explicit offset. A binding in the wrong time zone matches
 * nothing; `api-keys:notify-expiring` warns when it claims none of the notices
 * it tried. Success stamps
 * `expiry_notified_at` and clears the claim. Engines prove atomicity via
 * affected-row count === 1.
 */
final class ExpiryNoticeClaimSql
{
    /**
     * Minimal `api_keys` slice used by the four-engine CAS smoke.
     */
    public static function createTableSqlite(): string
    {
        return <<<'SQL'
            CREATE TABLE api_keys (
                uuid TEXT PRIMARY KEY NOT NULL,
                expires_at TEXT NULL,
                expiry_notified_at TEXT NULL,
                expiry_notice_claimed_at TEXT NULL,
                expiry_notice_claim_token TEXT NULL
            )
            SQL;
    }

    public static function createTableMysql(): string
    {
        return <<<'SQL'
            CREATE TABLE api_keys (
                uuid CHAR(36) PRIMARY KEY NOT NULL,
                expires_at DATETIME NULL,
                expiry_notified_at DATETIME NULL,
                expiry_notice_claimed_at DATETIME NULL,
                expiry_notice_claim_token VARCHAR(64) NULL
            )
            SQL;
    }

    public static function createTablePgsql(): string
    {
        return <<<'SQL'
            CREATE TABLE api_keys (
                uuid UUID PRIMARY KEY NOT NULL,
                expires_at TIMESTAMPTZ NULL,
                expiry_notified_at TIMESTAMPTZ NULL,
                expiry_notice_claimed_at TIMESTAMPTZ NULL,
                expiry_notice_claim_token VARCHAR(64) NULL
            )
            SQL;
    }

    /**
     * The `expires_at` bounds the claim statements match, for the expiry the
     * command selected: from the start of its second to one second later. This
     * covers truncated, kept and rounded fractions, while a rotation, which
     * moves the expiry by far more, never matches.
     *
     * @return array{0: \DateTimeImmutable, 1: \DateTimeImmutable} [expires_from, expires_until]
     */
    public static function expiryWindow(\DateTimeImmutable $selected): array
    {
        $from = $selected->setTime(
            (int) $selected->format('G'),
            (int) $selected->format('i'),
            (int) $selected->format('s'),
        );

        return [$from, $from->modify('+1 second')];
    }

    /**
     * Bindings: claimed_at, claim_token, uuid, expires_from, expires_until
     * ({@see expiryWindow()} of the selected expiry), lease_cutoff
     * (claimed_at - lease). Win when rowCount() === 1.
     */
    public static function claim(): string
    {
        return <<<'SQL'
            UPDATE api_keys
            SET expiry_notice_claimed_at = ?, expiry_notice_claim_token = ?
            WHERE uuid = ?
              AND expires_at >= ? AND expires_at <= ?
              AND expiry_notified_at IS NULL
              AND (
                  expiry_notice_claimed_at IS NULL
                  OR expiry_notice_claimed_at < ?
              )
            SQL;
    }

    /**
     * Bindings: notified_at, uuid, expires_from, expires_until, claim_token.
     * rowCount() === 0 means the claim was lost: nothing was stamped.
     */
    public static function markNotified(): string
    {
        return <<<'SQL'
            UPDATE api_keys
            SET expiry_notified_at = ?, expiry_notice_claimed_at = NULL, expiry_notice_claim_token = NULL
            WHERE uuid = ?
              AND expires_at >= ? AND expires_at <= ?
              AND expiry_notice_claim_token = ?
              AND expiry_notified_at IS NULL
            SQL;
    }

    /**
     * Bindings: uuid, expires_from, expires_until, claim_token. A rotation
     * during the send leaves the claim in place until its lease expires.
     */
    public static function release(): string
    {
        return <<<'SQL'
            UPDATE api_keys
            SET expiry_notice_claimed_at = NULL, expiry_notice_claim_token = NULL
            WHERE uuid = ?
              AND expires_at >= ? AND expires_at <= ?
              AND expiry_notice_claim_token = ?
              AND expiry_notified_at IS NULL
            SQL;
    }
}
