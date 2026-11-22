<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\Contracts\ApiKeyRecord;
use Qiick\ApiKeys\CredentialKind;
use Qiick\ApiKeys\RevocationReason;

/**
 * @api Mutable in-memory {@see ApiKeyRecord} for unit tests.
 */
final class InMemoryApiKeyRecord implements ApiKeyRecord
{
    /**
     * @param  list<string>|mixed  $scopes
     * @param  list<string>|null|mixed  $ipAllowlist
     * @param  array<string, mixed>  $metadata
     * @param  array<string, mixed>  $attributes
     */
    public function __construct(
        private string|int $id = 'key-1',
        private string $publicId = '00000000-0000-7000-8000-000000000001',
        private string $keyPrefix = 'tst_test_abcdefgh',
        private string $keyHash = '',
        private int $tokenVersion = 1,
        private string $hashAlgorithm = 'sha256',
        private ?string $previousKeyPrefix = null,
        private ?string $previousKeyHash = null,
        private ?\DateTimeImmutable $previousKeyValidUntil = null,
        private CredentialKind $credentialKind = CredentialKind::ApiKey,
        private ?string $oauthClientId = null,
        private ?string $description = null,
        private array $metadata = [],
        private mixed $scopes = ['items:read'],
        private mixed $ipAllowlist = null,
        private mixed $restrictions = null,
        private ?int $rateLimitPerMinute = null,
        private ?int $rateLimitPerDay = null,
        private ?int $rateLimitPerMonth = null,
        private ?\DateTimeImmutable $expiresAt = null,
        private ?\DateTimeImmutable $expiryNotifiedAt = null,
        private ?\DateTimeImmutable $revokedAt = null,
        private string|int|null $revokedByIdentifier = null,
        private ?RevocationReason $revokedReason = null,
        private ?string $revocationNote = null,
        private ?\DateTimeImmutable $exposedAt = null,
        private ?string $exposureSource = null,
        private ?\DateTimeImmutable $lastRotatedAt = null,
        private string|int|null $ownerIdentifier = 1,
        private ?string $ownerPrincipalIdentifier = null,
        private ?string $ownerKind = null,
        private string|int|null $createdByIdentifier = 1,
        private array $attributes = [],
        private ?\DateTimeImmutable $lastUsedAt = null,
        private ?string $lastUsedIp = null,
        private ?string $lastUsedUserAgent = null,
    ) {}

    public function id(): string|int
    {
        return $this->id;
    }

    public function publicId(): string
    {
        return $this->publicId;
    }

    public function keyPrefix(): string
    {
        return $this->keyPrefix;
    }

    public function keyHash(): string
    {
        return $this->keyHash;
    }

    public function tokenVersion(): int
    {
        return $this->tokenVersion;
    }

    public function hashAlgorithm(): string
    {
        return $this->hashAlgorithm;
    }

    public function previousKeyPrefix(): ?string
    {
        return $this->previousKeyPrefix;
    }

    public function previousKeyHash(): ?string
    {
        return $this->previousKeyHash;
    }

    public function previousKeyValidUntil(): ?\DateTimeImmutable
    {
        return $this->previousKeyValidUntil;
    }

    public function credentialKind(): CredentialKind
    {
        return $this->credentialKind;
    }

    public function oauthClientId(): ?string
    {
        return $this->oauthClientId;
    }

    public function description(): ?string
    {
        return $this->description;
    }

    public function metadata(): array
    {
        return $this->metadata;
    }

    public function rawScopes(): mixed
    {
        return $this->scopes;
    }

    public function rawIpAllowlist(): mixed
    {
        return $this->ipAllowlist;
    }

    public function rawRestrictions(): mixed
    {
        return $this->restrictions;
    }

    public function rateLimitPerMinute(): ?int
    {
        return $this->rateLimitPerMinute;
    }

    public function rateLimitPerDay(): ?int
    {
        return $this->rateLimitPerDay;
    }

    public function rateLimitPerMonth(): ?int
    {
        return $this->rateLimitPerMonth;
    }

    public function expiresAt(): ?\DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function expiryNotifiedAt(): ?\DateTimeImmutable
    {
        return $this->expiryNotifiedAt;
    }

    public function revokedAt(): ?\DateTimeImmutable
    {
        return $this->revokedAt;
    }

    public function revokedByIdentifier(): string|int|null
    {
        return $this->revokedByIdentifier;
    }

    public function revokedReason(): ?RevocationReason
    {
        return $this->revokedReason;
    }

    public function revocationNote(): ?string
    {
        return $this->revocationNote;
    }

    public function exposedAt(): ?\DateTimeImmutable
    {
        return $this->exposedAt;
    }

    public function exposureSource(): ?string
    {
        return $this->exposureSource;
    }

    public function lastRotatedAt(): ?\DateTimeImmutable
    {
        return $this->lastRotatedAt;
    }

    public function ownerIdentifier(): string|int|null
    {
        return $this->ownerIdentifier;
    }

    public function ownerPrincipalIdentifier(): ?string
    {
        return $this->ownerPrincipalIdentifier;
    }

    public function ownerKind(): ?string
    {
        return $this->ownerKind;
    }

    public function createdByIdentifier(): string|int|null
    {
        return $this->createdByIdentifier;
    }

    public function attributes(): array
    {
        return $this->attributes;
    }

    public function lastUsedAt(): ?\DateTimeImmutable
    {
        return $this->lastUsedAt;
    }

    public function lastUsedIp(): ?string
    {
        return $this->lastUsedIp;
    }

    public function lastUsedUserAgent(): ?string
    {
        return $this->lastUsedUserAgent;
    }

    public function withKeyHash(string $keyHash): self
    {
        $clone = clone $this;
        $clone->keyHash = $keyHash;

        return $clone;
    }

    public function withPublicId(string $publicId): self
    {
        $clone = clone $this;
        $clone->publicId = $publicId;

        return $clone;
    }

    public function withTokenVersion(int $tokenVersion): self
    {
        $clone = clone $this;
        $clone->tokenVersion = $tokenVersion;

        return $clone;
    }

    public function withHashAlgorithm(string $hashAlgorithm): self
    {
        $clone = clone $this;
        $clone->hashAlgorithm = $hashAlgorithm;

        return $clone;
    }

    public function withPrevious(
        ?string $previousKeyHash,
        ?\DateTimeImmutable $previousKeyValidUntil,
        ?string $previousKeyPrefix = null,
    ): self {
        $clone = clone $this;
        $clone->previousKeyHash = $previousKeyHash;
        $clone->previousKeyValidUntil = $previousKeyValidUntil;
        $clone->previousKeyPrefix = $previousKeyPrefix;

        return $clone;
    }

    public function withCredentialKind(CredentialKind $credentialKind): self
    {
        $clone = clone $this;
        $clone->credentialKind = $credentialKind;

        return $clone;
    }

    public function withOauthClientId(?string $oauthClientId): self
    {
        $clone = clone $this;
        $clone->oauthClientId = $oauthClientId;

        return $clone;
    }

    public function withRestrictions(mixed $restrictions): self
    {
        $clone = clone $this;
        $clone->restrictions = $restrictions;

        return $clone;
    }

    /**
     * @param  array<string, mixed>  $metadata
     */
    public function withMetadata(array $metadata): self
    {
        $clone = clone $this;
        $clone->metadata = $metadata;

        return $clone;
    }

    public function withRevokedAt(?\DateTimeImmutable $revokedAt): self
    {
        $clone = clone $this;
        $clone->revokedAt = $revokedAt;

        return $clone;
    }

    public function withRevocation(
        ?\DateTimeImmutable $revokedAt,
        string|int|null $revokedByIdentifier,
        ?RevocationReason $revokedReason,
        ?string $revocationNote = null,
    ): self {
        $clone = clone $this;
        $clone->revokedAt = $revokedAt;
        $clone->revokedByIdentifier = $revokedByIdentifier;
        $clone->revokedReason = $revokedReason;
        $clone->revocationNote = $revocationNote;

        return $clone;
    }

    public function withExpiresAt(?\DateTimeImmutable $expiresAt): self
    {
        $clone = clone $this;
        $clone->expiresAt = $expiresAt;

        return $clone;
    }

    public function withExpiryNotifiedAt(?\DateTimeImmutable $expiryNotifiedAt): self
    {
        $clone = clone $this;
        $clone->expiryNotifiedAt = $expiryNotifiedAt;

        return $clone;
    }

    public function withExposedAt(?\DateTimeImmutable $exposedAt, ?string $exposureSource = null): self
    {
        $clone = clone $this;
        $clone->exposedAt = $exposedAt;
        $clone->exposureSource = $exposureSource;

        return $clone;
    }

    public function withScopes(mixed $scopes): self
    {
        $clone = clone $this;
        $clone->scopes = $scopes;

        return $clone;
    }

    public function withIpAllowlist(mixed $ipAllowlist): self
    {
        $clone = clone $this;
        $clone->ipAllowlist = $ipAllowlist;

        return $clone;
    }

    public function withRateLimitPerMinute(?int $rateLimitPerMinute): self
    {
        $clone = clone $this;
        $clone->rateLimitPerMinute = $rateLimitPerMinute;

        return $clone;
    }

    public function withRateLimitPerDay(?int $rateLimitPerDay): self
    {
        $clone = clone $this;
        $clone->rateLimitPerDay = $rateLimitPerDay;

        return $clone;
    }

    public function withRateLimitPerMonth(?int $rateLimitPerMonth): self
    {
        $clone = clone $this;
        $clone->rateLimitPerMonth = $rateLimitPerMonth;

        return $clone;
    }

    public function withLastUsed(
        ?\DateTimeImmutable $lastUsedAt,
        ?string $lastUsedIp,
        ?string $lastUsedUserAgent = null,
    ): self {
        $clone = clone $this;
        $clone->lastUsedAt = $lastUsedAt;
        $clone->lastUsedIp = $lastUsedIp;
        $clone->lastUsedUserAgent = $lastUsedUserAgent;

        return $clone;
    }

    public function withOwnerIdentifier(string|int|null $ownerIdentifier): self
    {
        $clone = clone $this;
        $clone->ownerIdentifier = $ownerIdentifier;

        return $clone;
    }

    public function withCreatedByIdentifier(string|int|null $createdByIdentifier): self
    {
        $clone = clone $this;
        $clone->createdByIdentifier = $createdByIdentifier;

        return $clone;
    }

    public function withLastRotatedAt(?\DateTimeImmutable $lastRotatedAt): self
    {
        $clone = clone $this;
        $clone->lastRotatedAt = $lastRotatedAt;

        return $clone;
    }
}
