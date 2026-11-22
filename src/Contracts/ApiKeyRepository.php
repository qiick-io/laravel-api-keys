<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

use Qiick\ApiKeys\ExpiryNoticeClaimSql;

/**
 * @api Product binds the persistence adapter.
 */
interface ApiKeyRepository
{
    /**
     * Candidates whose `key_prefix` matches, or whose `previous_key_prefix`
     * matches inside the grace window (`previous_key_valid_until`).
     *
     * @return iterable<ApiKeyRecord>
     */
    public function findCandidatesByPrefix(#[\SensitiveParameter] string $keyPrefix): iterable;

    public function findByPublicId(string $publicId): ?ApiKeyRecord;

    /**
     * Persist last_used_* via saveQuietly; must not bump updated_at.
     * Truncate `$userAgent` to 512 characters before storage.
     */
    public function recordUsage(
        ApiKeyRecord $record,
        ?string $ip,
        ?string $userAgent,
        \DateTimeImmutable $usedAt,
    ): void;

    /**
     * Non-revoked `api_key` rows with `expires_at` ≤ `$until` and null
     * `expiry_notified_at`.
     *
     * @return iterable<ApiKeyRecord>
     */
    public function expiringUnnotified(\DateTimeImmutable $until): iterable;

    /**
     * Final success stamp: set `expiry_notified_at` and clear
     * `expiry_notice_claimed_at`. Call only after a successful send.
     */
    public function markExpiryNotified(ApiKeyRecord $record, \DateTimeImmutable $notifiedAt): void;

    /**
     * Atomic claim lease on `expiry_notice_claimed_at` (see
     * {@see ExpiryNoticeClaimSql::claim()}). Wins when the
     * notice is unsent and either unclaimed or the prior claim is older than
     * `$leaseSeconds`. Claim before send; {@see releaseExpiryNotice()} on
     * send failure; {@see markExpiryNotified()} after success.
     */
    public function claimExpiryNotice(
        ApiKeyRecord $record,
        \DateTimeImmutable $now,
        int $leaseSeconds,
    ): bool;

    /**
     * Clear `expiry_notice_claimed_at` after a failed send so the next run
     * can reclaim immediately (without waiting for the lease).
     */
    public function releaseExpiryNotice(ApiKeyRecord $record): void;

    /**
     * Non-revoked `api_key` rows still on token_version 0 (product legacy format).
     *
     * @return iterable<ApiKeyRecord>
     */
    public function findActiveLegacy(): iterable;
}
