<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

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

    public function markExpiryNotified(ApiKeyRecord $record, \DateTimeImmutable $notifiedAt): void;

    /**
     * Non-revoked `api_key` rows still on token_version 0 (product legacy format).
     *
     * @return iterable<ApiKeyRecord>
     */
    public function findActiveLegacy(): iterable;
}
