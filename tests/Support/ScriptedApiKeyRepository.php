<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Tests\Support;

use DateTimeImmutable;
use Qiick\ApiKeys\Contracts\ApiKeyRecord;
use Qiick\ApiKeys\Contracts\ApiKeyRepository;

/**
 * Test double for api-keys:notify-expiring: returns fixed lists, including rows a
 * real query would never return (a null expiry), refuses the claims it is told
 * to, and records every claim, release and mark.
 */
final class ScriptedApiKeyRepository implements ApiKeyRepository
{
    /** @var list<string> */
    public array $claimedPublicIds = [];

    /** @var list<string> */
    public array $releasedPublicIds = [];

    /** @var list<string> */
    public array $markedPublicIds = [];

    /** @var list<int> */
    public array $claimLeaseSeconds = [];

    public ?DateTimeImmutable $expiringUntil = null;

    /**
     * @param  list<ApiKeyRecord>  $expiring
     * @param  list<ApiKeyRecord>  $activeLegacy
     * @param  list<string>  $lostClaimPublicIds  claims another worker already holds
     */
    public function __construct(
        private array $expiring = [],
        private array $activeLegacy = [],
        private array $lostClaimPublicIds = [],
    ) {}

    public function findCandidatesByPrefix(#[\SensitiveParameter] string $keyPrefix): iterable
    {
        return [];
    }

    public function findByPublicId(string $publicId): ?ApiKeyRecord
    {
        return null;
    }

    public function expiringUnnotified(DateTimeImmutable $until): iterable
    {
        $this->expiringUntil = $until;

        return $this->expiring;
    }

    public function markExpiryNotified(ApiKeyRecord $record, DateTimeImmutable $notifiedAt): void
    {
        $this->markedPublicIds[] = $record->publicId();
    }

    public function claimExpiryNotice(ApiKeyRecord $record, DateTimeImmutable $now, int $leaseSeconds): bool
    {
        $this->claimLeaseSeconds[] = $leaseSeconds;

        if (in_array($record->publicId(), $this->lostClaimPublicIds, true)) {
            return false;
        }

        $this->claimedPublicIds[] = $record->publicId();

        return true;
    }

    public function releaseExpiryNotice(ApiKeyRecord $record): void
    {
        $this->releasedPublicIds[] = $record->publicId();
    }

    public function findActiveLegacy(): iterable
    {
        return $this->activeLegacy;
    }

    public function recordUsage(ApiKeyRecord $record, ?string $ip, ?string $userAgent, DateTimeImmutable $usedAt): void {}
}
