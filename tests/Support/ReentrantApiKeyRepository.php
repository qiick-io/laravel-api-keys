<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Tests\Support;

use Closure;
use DateTimeImmutable;
use Qiick\ApiKeys\Contracts\ApiKeyRecord;
use Qiick\ApiKeys\Contracts\ApiKeyRepository;

/**
 * Test double that simulates a second request arriving while the first one is
 * still being verified: the first key lookup runs the injected request before
 * returning its candidates, like a slow database under parallel traffic.
 */
final class ReentrantApiKeyRepository implements ApiKeyRepository
{
    private ?Closure $concurrentRequest = null;

    public function __construct(
        private ApiKeyRepository $inner,
    ) {}

    public function interleave(Closure $concurrentRequest): void
    {
        $this->concurrentRequest = $concurrentRequest;
    }

    public function findCandidatesByPrefix(#[\SensitiveParameter] string $keyPrefix): iterable
    {
        $concurrentRequest = $this->concurrentRequest;
        $this->concurrentRequest = null;

        if ($concurrentRequest !== null) {
            $concurrentRequest();
        }

        return $this->inner->findCandidatesByPrefix($keyPrefix);
    }

    public function findByPublicId(string $publicId): ?ApiKeyRecord
    {
        return $this->inner->findByPublicId($publicId);
    }

    public function expiringUnnotified(DateTimeImmutable $until): iterable
    {
        return $this->inner->expiringUnnotified($until);
    }

    public function markExpiryNotified(ApiKeyRecord $record, DateTimeImmutable $notifiedAt, string $claimToken): bool
    {
        return $this->inner->markExpiryNotified($record, $notifiedAt, $claimToken);
    }

    public function claimExpiryNotice(ApiKeyRecord $record, DateTimeImmutable $now, int $leaseSeconds, string $claimToken): bool
    {
        return $this->inner->claimExpiryNotice($record, $now, $leaseSeconds, $claimToken);
    }

    public function releaseExpiryNotice(ApiKeyRecord $record, string $claimToken): void
    {
        $this->inner->releaseExpiryNotice($record, $claimToken);
    }

    public function findActiveLegacy(): iterable
    {
        return $this->inner->findActiveLegacy();
    }

    public function recordUsage(ApiKeyRecord $record, ?string $ip, ?string $userAgent, DateTimeImmutable $usedAt): void
    {
        $this->inner->recordUsage($record, $ip, $userAgent, $usedAt);
    }
}
