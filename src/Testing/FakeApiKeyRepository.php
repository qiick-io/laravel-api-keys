<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\Contracts\ApiKeyRecord;
use Qiick\ApiKeys\Contracts\ApiKeyRepository;
use Qiick\ApiKeys\CredentialKind;
use Qiick\ApiKeys\ExpiryNoticeClaimSql;

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

    /**
     * The token of the live expiry-notice claim per public id
     * (`expiry_notice_claim_token`).
     *
     * @var array<string, string>
     */
    private array $claimTokens = [];

    /**
     * Every token passed to a claim, in call order.
     *
     * @var list<string>
     */
    public array $claimTokensUsed = [];

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

    public function markExpiryNotified(ApiKeyRecord $record, \DateTimeImmutable $notifiedAt, string $claimToken): bool
    {
        $publicId = $record->publicId();
        $current = $this->findByPublicId($publicId) ?? $record;

        if (! $this->holdsClaim($current, $record, $claimToken)) {
            return false;
        }

        $this->casVersions[$publicId] = ($this->casVersions[$publicId] ?? 0) + 1;
        unset($this->claimTokens[$publicId]);
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

        return true;
    }

    public function claimExpiryNotice(
        ApiKeyRecord $record,
        \DateTimeImmutable $now,
        int $leaseSeconds,
        string $claimToken,
    ): bool {
        return $this->claimExpiryNoticeWithObservedVersion(
            $record,
            $now,
            $leaseSeconds,
            $this->casVersions[$record->publicId()] ?? 0,
            $claimToken,
        );
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
        string $claimToken,
    ): bool {
        $publicId = $record->publicId();
        $current = $this->findByPublicId($publicId) ?? $record;
        $this->claimTokensUsed[] = $claimToken;

        if ($current->expiryNotifiedAt() !== null || ! $this->isSameExpiry($current, $record)) {
            return false;
        }

        $claimedAt = $current->expiryNoticeClaimedAt();
        if ($claimedAt !== null && $claimedAt >= $now->modify('-'.$leaseSeconds.' seconds')) {
            return false;
        }

        if (($this->casVersions[$publicId] ?? 0) !== $observedVersion) {
            return false;
        }

        $this->casVersions[$publicId] = $observedVersion + 1;
        $this->claimTokens[$publicId] = $claimToken;

        if ($current instanceof InMemoryApiKeyRecord) {
            $this->replaceRecord($publicId, $current->withExpiryNoticeClaimedAt($now));
        }

        return true;
    }

    public function releaseExpiryNotice(ApiKeyRecord $record, string $claimToken): void
    {
        $publicId = $record->publicId();
        $current = $this->findByPublicId($publicId) ?? $record;

        if (! $this->holdsClaim($current, $record, $claimToken)) {
            return;
        }

        $this->casVersions[$publicId] = ($this->casVersions[$publicId] ?? 0) + 1;
        unset($this->claimTokens[$publicId]);

        if ($current instanceof InMemoryApiKeyRecord) {
            $this->replaceRecord($publicId, $current->withExpiryNoticeClaimedAt(null));
        }
    }

    /**
     * Like {@see ExpiryNoticeClaimSql::markNotified()} and `release()`: the row is
     * unsent, still holds this claim's token, and still has the selected expiry.
     */
    private function holdsClaim(ApiKeyRecord $current, ApiKeyRecord $selected, string $claimToken): bool
    {
        return $current->expiryNotifiedAt() === null
            && ($this->claimTokens[$current->publicId()] ?? null) === $claimToken
            && $this->isSameExpiry($current, $selected);
    }

    private function isSameExpiry(ApiKeyRecord $current, ApiKeyRecord $selected): bool
    {
        return $current->expiresAt()?->format('U.u') === $selected->expiresAt()?->format('U.u');
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
