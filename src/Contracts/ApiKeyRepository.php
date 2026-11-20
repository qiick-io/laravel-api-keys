<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

/**
 * @api Product binds the persistence adapter.
 */
interface ApiKeyRepository
{
    /**
     * @return iterable<ApiKeyRecord>
     */
    public function findCandidatesByPrefix(#[\SensitiveParameter] string $keyPrefix): iterable;

    /**
     * Persist last_used_* via saveQuietly; must not bump updated_at.
     */
    public function recordUsage(ApiKeyRecord $record, ?string $ip, \DateTimeImmutable $usedAt): void;
}
