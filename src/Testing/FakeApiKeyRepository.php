<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\Contracts\ApiKeyRecord;
use Qiick\ApiKeys\Contracts\ApiKeyRepository;
use Qiick\ApiKeys\CredentialKind;

/**
 * @api In-memory repository for authenticator tests.
 *
 * Expiry-notice claim uses a per-key monotonic CAS version so a stale
 * observed version cannot win after another writer advanced the row
 * (mirrors `UPDATE … WHERE …` affected-row semantics).
 */
final class FakeApiKeyRepository implements ApiKeyRepository
{
    use EnsuresTestingEnvironmentTrait;

    public const int USER_AGENT_MAX_LENGTH = 512;

    /** @var list<ApiKeyRecord> */
    private array $records;

    /** @var list<array{record: ApiKeyRecord, ip: ?string, userAgent: ?string, usedAt: \DateTimeImmutable}> */
    public array $recordedUsages = [];

    /** @var list<array{record: ApiKeyRecord, notifiedAt: \DateTimeImmutable}> */
    public array $expiryNotifications = [];

    /**
     * Monotonic CAS token per public id (claim / mark / release).
     *
     * @var array<string, int>
     */
    private array $casVersions = [];

    private ?\DateTimeImmutable $now;

    /**
     * @param  list<ApiKeyRecord>  $records
     */
    public function __construct(array $records = [], ?\DateTimeImmutable $now = null)
    {
        self::ensureTestingEnvironment();

        $this->records = $records;
        $this->now = $now;
    }

    /**
     * @return list<ApiKeyRecord>
     */
    public function findCandidatesByPrefix(#[\SensitiveParameter] string $keyPrefix): iterable
    {
        $matches = [];
        $now = $this->now ?? new \DateTimeImmutable('now');

        foreach ($this->records as $record) {
            if ($record->keyPrefix() === $keyPrefix) {
                $matches[] = $record;

                continue;
            }

            if (
                $record->previousKeyPrefix() === $keyPrefix
                && $record->previousKeyValidUntil() !== null
                && $now < $record->previousKeyValidUntil()
            ) {
                $matches[] = $record;
            }
        }

        return $matches;
    }

    public function findByPublicId(string $publicId): ?ApiKeyRecord
    {
        foreach ($this->records as $record) {
            if ($record->publicId() === $publicId) {
                return $record;
            }
        }

        return null;
    }

    public function recordUsage(
        ApiKeyRecord $record,
        ?string $ip,
        ?string $userAgent,
        \DateTimeImmutable $usedAt,
    ): void {
        if ($userAgent !== null && strlen($userAgent) > self::USER_AGENT_MAX_LENGTH) {
            $userAgent = substr($userAgent, 0, self::USER_AGENT_MAX_LENGTH);
        }

        $this->recordedUsages[] = [
            'record' => $record,
            'ip' => $ip,
            'userAgent' => $userAgent,
            'usedAt' => $usedAt,
        ];
    }

    public function expiringUnnotified(\DateTimeImmutable $until): iterable
    {
        $matches = [];

        foreach ($this->records as $record) {
            if ($record->credentialKind() !== CredentialKind::ApiKey) {
                continue;
            }

            if ($record->revokedAt() !== null) {
                continue;
            }

            if ($record->expiryNotifiedAt() !== null) {
                continue;
            }

            $expiresAt = $record->expiresAt();
            if ($expiresAt === null || $expiresAt > $until) {
                continue;
            }

            $matches[] = $record;
        }

        return $matches;
    }

    public function markExpiryNotified(ApiKeyRecord $record, \DateTimeImmutable $notifiedAt): void
    {
        $publicId = $record->publicId();
        $observedVersion = $this->casVersions[$publicId] ?? 0;
        $current = $this->findByPublicId($publicId) ?? $record;

        if ($current->expiryNotifiedAt() !== null) {
            return;
        }

        if (($this->casVersions[$publicId] ?? 0) !== $observedVersion) {
            return;
        }

        $this->casVersions[$publicId] = $observedVersion + 1;
        $this->expiryNotifications[] = [
            'record' => $current,
            'notifiedAt' => $notifiedAt,
        ];

        if ($current instanceof InMemoryApiKeyRecord) {
            $updated = $current
                ->withExpiryNotifiedAt($notifiedAt)
                ->withExpiryNoticeClaimedAt(null);
            $this->replaceRecord($publicId, $updated);
        }
    }

    public function claimExpiryNotice(
        ApiKeyRecord $record,
        \DateTimeImmutable $now,
        int $leaseSeconds,
    ): bool {
        $publicId = $record->publicId();
        $observedVersion = $this->casVersions[$publicId] ?? 0;
        $current = $this->findByPublicId($publicId) ?? $record;

        if ($current->expiryNotifiedAt() !== null) {
            return false;
        }

        $claimedAt = $current->expiryNoticeClaimedAt();
        if ($claimedAt !== null) {
            $leaseCutoff = $now->modify('-'.$leaseSeconds.' seconds');

            if ($claimedAt >= $leaseCutoff) {
                return false;
            }
        }

        if (($this->casVersions[$publicId] ?? 0) !== $observedVersion) {
            return false;
        }

        $this->casVersions[$publicId] = $observedVersion + 1;

        if ($current instanceof InMemoryApiKeyRecord) {
            $this->replaceRecord($publicId, $current->withExpiryNoticeClaimedAt($now));
        }

        return true;
    }

    /**
     * Observe the current CAS version for a key (tests that simulate a stale writer).
     */
    public function casVersionFor(string $publicId): int
    {
        return $this->casVersions[$publicId] ?? 0;
    }

    /**
     * Attempt a claim that already observed `$observedVersion` (stale CAS probe).
     */
    public function claimExpiryNoticeWithObservedVersion(
        ApiKeyRecord $record,
        \DateTimeImmutable $now,
        int $leaseSeconds,
        int $observedVersion,
    ): bool {
        $publicId = $record->publicId();
        $current = $this->findByPublicId($publicId) ?? $record;

        if ($current->expiryNotifiedAt() !== null) {
            return false;
        }

        $claimedAt = $current->expiryNoticeClaimedAt();
        if ($claimedAt !== null) {
            $leaseCutoff = $now->modify('-'.$leaseSeconds.' seconds');

            if ($claimedAt >= $leaseCutoff) {
                return false;
            }
        }

        if (($this->casVersions[$publicId] ?? 0) !== $observedVersion) {
            return false;
        }

        $this->casVersions[$publicId] = $observedVersion + 1;

        if ($current instanceof InMemoryApiKeyRecord) {
            $this->replaceRecord($publicId, $current->withExpiryNoticeClaimedAt($now));
        }

        return true;
    }

    public function releaseExpiryNotice(ApiKeyRecord $record): void
    {
        $publicId = $record->publicId();
        $observedVersion = $this->casVersions[$publicId] ?? 0;
        $current = $this->findByPublicId($publicId) ?? $record;

        if ($current->expiryNotifiedAt() !== null) {
            return;
        }

        if (($this->casVersions[$publicId] ?? 0) !== $observedVersion) {
            return;
        }

        $this->casVersions[$publicId] = $observedVersion + 1;

        if ($current instanceof InMemoryApiKeyRecord) {
            $this->replaceRecord($publicId, $current->withExpiryNoticeClaimedAt(null));
        }
    }

    public function findActiveLegacy(): iterable
    {
        $matches = [];

        foreach ($this->records as $record) {
            if ($record->credentialKind() !== CredentialKind::ApiKey) {
                continue;
            }

            if ($record->revokedAt() !== null) {
                continue;
            }

            if ($record->tokenVersion() !== 0) {
                continue;
            }

            $matches[] = $record;
        }

        return $matches;
    }

    /**
     * @param  list<ApiKeyRecord>  $records
     */
    public function setRecords(array $records): void
    {
        $this->records = $records;
    }

    public function withNow(\DateTimeImmutable $now): self
    {
        $clone = clone $this;
        $clone->now = $now;

        return $clone;
    }

    private function replaceRecord(string $publicId, InMemoryApiKeyRecord $updated): void
    {
        foreach ($this->records as $index => $existing) {
            if ($existing->publicId() === $publicId) {
                $this->records[$index] = $updated;
            }
        }
    }
}
