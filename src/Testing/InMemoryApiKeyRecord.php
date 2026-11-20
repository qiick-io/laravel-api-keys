<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\Contracts\ApiKeyRecord;

/**
 * @api Mutable in-memory {@see ApiKeyRecord} for unit tests.
 */
final class InMemoryApiKeyRecord implements ApiKeyRecord
{
    /**
     * @param  list<string>|mixed  $scopes
     * @param  list<string>|null|mixed  $ipAllowlist
     * @param  array<string, mixed>  $attributes
     */
    public function __construct(
        private string|int $id = 'key-1',
        private string $keyPrefix = 'tst_test_abcdefgh',
        private string $keyHash = '',
        private ?string $previousKeyHash = null,
        private ?\DateTimeImmutable $previousKeyValidUntil = null,
        private mixed $scopes = ['items:read'],
        private mixed $ipAllowlist = null,
        private ?int $rateLimitPerMinute = null,
        private ?\DateTimeImmutable $expiresAt = null,
        private ?\DateTimeImmutable $revokedAt = null,
        private string|int|null $ownerIdentifier = 1,
        private string|int|null $createdByIdentifier = 1,
        private array $attributes = [],
        private ?\DateTimeImmutable $lastUsedAt = null,
        private ?string $lastUsedIp = null,
    ) {}

    public function id(): string|int
    {
        return $this->id;
    }

    public function keyPrefix(): string
    {
        return $this->keyPrefix;
    }

    public function keyHash(): string
    {
        return $this->keyHash;
    }

    public function previousKeyHash(): ?string
    {
        return $this->previousKeyHash;
    }

    public function previousKeyValidUntil(): ?\DateTimeImmutable
    {
        return $this->previousKeyValidUntil;
    }

    public function rawScopes(): mixed
    {
        return $this->scopes;
    }

    public function rawIpAllowlist(): mixed
    {
        return $this->ipAllowlist;
    }

    public function rateLimitPerMinute(): ?int
    {
        return $this->rateLimitPerMinute;
    }

    public function expiresAt(): ?\DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function revokedAt(): ?\DateTimeImmutable
    {
        return $this->revokedAt;
    }

    public function ownerIdentifier(): string|int|null
    {
        return $this->ownerIdentifier;
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

    public function withKeyHash(string $keyHash): self
    {
        $clone = clone $this;
        $clone->keyHash = $keyHash;

        return $clone;
    }

    public function withPrevious(
        ?string $previousKeyHash,
        ?\DateTimeImmutable $previousKeyValidUntil,
    ): self {
        $clone = clone $this;
        $clone->previousKeyHash = $previousKeyHash;
        $clone->previousKeyValidUntil = $previousKeyValidUntil;

        return $clone;
    }

    public function withRevokedAt(?\DateTimeImmutable $revokedAt): self
    {
        $clone = clone $this;
        $clone->revokedAt = $revokedAt;

        return $clone;
    }

    public function withExpiresAt(?\DateTimeImmutable $expiresAt): self
    {
        $clone = clone $this;
        $clone->expiresAt = $expiresAt;

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

    public function withLastUsed(?\DateTimeImmutable $lastUsedAt, ?string $lastUsedIp): self
    {
        $clone = clone $this;
        $clone->lastUsedAt = $lastUsedAt;
        $clone->lastUsedIp = $lastUsedIp;

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
}
