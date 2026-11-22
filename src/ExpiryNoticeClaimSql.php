<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Portable SQL for the expiry-notice claim lease (products / engine smoke).
 *
 * Claim sets `expiry_notice_claimed_at` only when the notice is still unsent and
 * either unclaimed or the prior claim is older than the lease. Success stamps
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
                expiry_notified_at TEXT NULL,
                expiry_notice_claimed_at TEXT NULL
            )
            SQL;
    }

    public static function createTableMysql(): string
    {
        return <<<'SQL'
            CREATE TABLE api_keys (
                uuid CHAR(36) PRIMARY KEY NOT NULL,
                expiry_notified_at DATETIME NULL,
                expiry_notice_claimed_at DATETIME NULL
            )
            SQL;
    }

    public static function createTablePgsql(): string
    {
        return <<<'SQL'
            CREATE TABLE api_keys (
                uuid UUID PRIMARY KEY NOT NULL,
                expiry_notified_at TIMESTAMPTZ NULL,
                expiry_notice_claimed_at TIMESTAMPTZ NULL
            )
            SQL;
    }

    /**
     * Bindings: claimed_at, uuid, lease_cutoff (claimed_at - lease).
     * Win when rowCount() === 1.
     */
    public static function claim(): string
    {
        return <<<'SQL'
            UPDATE api_keys
            SET expiry_notice_claimed_at = ?
            WHERE uuid = ?
              AND expiry_notified_at IS NULL
              AND (
                  expiry_notice_claimed_at IS NULL
                  OR expiry_notice_claimed_at < ?
              )
            SQL;
    }

    /**
     * Bindings: notified_at, uuid.
     */
    public static function markNotified(): string
    {
        return <<<'SQL'
            UPDATE api_keys
            SET expiry_notified_at = ?, expiry_notice_claimed_at = NULL
            WHERE uuid = ?
              AND expiry_notified_at IS NULL
            SQL;
    }

    /**
     * Bindings: uuid.
     */
    public static function release(): string
    {
        return <<<'SQL'
            UPDATE api_keys
            SET expiry_notice_claimed_at = NULL
            WHERE uuid = ?
              AND expiry_notified_at IS NULL
            SQL;
    }
}
