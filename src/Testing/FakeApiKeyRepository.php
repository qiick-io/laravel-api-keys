<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\Contracts\ApiKeyRecord;
use Qiick\ApiKeys\Contracts\ApiKeyRepository;
use Qiick\ApiKeys\CredentialKind;

/**
 * @api In-memory repository for authenticator tests.
 */
final class FakeApiKeyRepository implements ApiKeyRepository
{
    public const int USER_AGENT_MAX_LENGTH = 512;

    /** @var list<ApiKeyRecord> */
    private array $records;

    /** @var list<array{record: ApiKeyRecord, ip: ?string, userAgent: ?string, usedAt: \DateTimeImmutable}> */
    public array $recordedUsages = [];

    /** @var list<array{record: ApiKeyRecord, notifiedAt: \DateTimeImmutable}> */
    public array $expiryNotifications = [];

    private ?\DateTimeImmutable $now;

    /**
     * @param  list<ApiKeyRecord>  $records
     */
    public function __construct(array $records = [], ?\DateTimeImmutable $now = null)
    {
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
        $this->expiryNotifications[] = [
            'record' => $record,
            'notifiedAt' => $notifiedAt,
        ];

        if ($record instanceof InMemoryApiKeyRecord) {
            $updated = $record->withExpiryNotifiedAt($notifiedAt);
            foreach ($this->records as $index => $existing) {
                if ($existing === $record || $existing->publicId() === $record->publicId()) {
                    $this->records[$index] = $updated;
                }
            }
        }
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
}
