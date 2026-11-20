<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

/**
 * @api Product-owned key row as seen by the authenticator (no Eloquent coupling).
 */
interface ApiKeyRecord
{
    public function id(): string|int;

    public function keyPrefix(): string;

    public function keyHash(): string;

    public function previousKeyHash(): ?string;

    public function previousKeyValidUntil(): ?\DateTimeImmutable;

    public function rawScopes(): mixed;

    public function rawIpAllowlist(): mixed;

    public function rateLimitPerMinute(): ?int;

    public function expiresAt(): ?\DateTimeImmutable;

    public function revokedAt(): ?\DateTimeImmutable;

    public function ownerIdentifier(): string|int|null;

    public function createdByIdentifier(): string|int|null;

    /**
     * @return array<string, mixed>
     */
    public function attributes(): array;

    public function lastUsedAt(): ?\DateTimeImmutable;

    public function lastUsedIp(): ?string;
}
