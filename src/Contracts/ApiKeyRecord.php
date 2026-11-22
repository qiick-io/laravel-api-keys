<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

use Qiick\ApiKeys\CredentialKind;
use Qiick\ApiKeys\KeyRestrictions;
use Qiick\ApiKeys\RevocationReason;

/**
 * @api Product-owned key row as seen by the authenticator (no Eloquent coupling).
 */
interface ApiKeyRecord
{
    /**
     * Internal persistence id. Prefer {@see publicId()} outside the database.
     */
    public function id(): string|int;

    /**
     * Public UUID used on the wire and in audit (`api_key_id`).
     */
    public function publicId(): string;

    public function keyPrefix(): string;

    public function keyHash(): string;

    /**
     * Issuance shape: 0 legacy, 1 canonical, 2 checksum. Unknown → fail closed.
     */
    public function tokenVersion(): int;

    /**
     * Digest algorithm name (e.g. `sha256`). Unknown → fail closed.
     */
    public function hashAlgorithm(): string;

    public function previousKeyPrefix(): ?string;

    public function previousKeyHash(): ?string;

    public function previousKeyValidUntil(): ?\DateTimeImmutable;

    public function credentialKind(): CredentialKind;

    public function oauthClientId(): ?string;

    public function description(): ?string;

    /**
     * @return array<string, mixed>
     */
    public function metadata(): array;

    public function rawScopes(): mixed;

    public function rawIpAllowlist(): mixed;

    /**
     * Raw `restrictions` JSON / array (parsed by {@see KeyRestrictions}).
     */
    public function rawRestrictions(): mixed;

    public function rateLimitPerMinute(): ?int;

    public function rateLimitPerDay(): ?int;

    public function rateLimitPerMonth(): ?int;

    public function expiresAt(): ?\DateTimeImmutable;

    public function expiryNotifiedAt(): ?\DateTimeImmutable;

    /**
     * Lease timestamp for an in-flight expiry notice claim; null when idle.
     */
    public function expiryNoticeClaimedAt(): ?\DateTimeImmutable;

    public function revokedAt(): ?\DateTimeImmutable;

    public function revokedByIdentifier(): string|int|null;

    public function revokedReason(): ?RevocationReason;

    public function revocationNote(): ?string;

    public function exposedAt(): ?\DateTimeImmutable;

    public function exposureSource(): ?string;

    public function lastRotatedAt(): ?\DateTimeImmutable;

    public function ownerIdentifier(): string|int|null;

    /**
     * Owner principal public id when the product uses principals; else null.
     */
    public function ownerPrincipalIdentifier(): ?string;

    /**
     * Kind from the principal (`user` / `service`), never a column on `api_keys`.
     */
    public function ownerKind(): ?string;

    public function createdByIdentifier(): string|int|null;

    /**
     * @return array<string, mixed>
     */
    public function attributes(): array;

    public function lastUsedAt(): ?\DateTimeImmutable;

    public function lastUsedIp(): ?string;

    public function lastUsedUserAgent(): ?string;
}
