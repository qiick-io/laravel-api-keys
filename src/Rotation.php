<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Result of rotating a key's secret (plaintext returned once).
 *
 * Note: `(array)` / `var_export` still expose public properties; prefer
 * `__debugInfo` / `json_encode` / `serialize`.
 *
 * Products must persist `previous_key_prefix` when set so the old token (incl.
 * a legacy prefix) stays findable during the grace window.
 */
final readonly class Rotation implements \JsonSerializable
{
    public function __construct(
        #[\SensitiveParameter] public string $newPlainText,
        public string $newKeyPrefix,
        #[\SensitiveParameter] public string $newKeyHash,
        #[\SensitiveParameter] public ?string $previousKeyHash,
        public ?\DateTimeImmutable $previousKeyValidUntil,
        public \DateTimeImmutable $lastRotatedAt,
        public int $tokenVersion = TokenCodec::DEFAULT_TOKEN_VERSION,
        public ?string $previousKeyPrefix = null,
    ) {}

    /**
     * @return array{newKeyPrefix: string, newKeyHash: string, previousKeyHash: string|null, previousKeyValidUntil: string|null, previousKeyPrefix: string|null, lastRotatedAt: string, tokenVersion: int, newPlainText: string}
     */
    public function __debugInfo(): array
    {
        return [
            'newKeyPrefix' => $this->newKeyPrefix,
            'newKeyHash' => '[REDACTED]',
            'previousKeyHash' => $this->previousKeyHash === null ? null : '[REDACTED]',
            'previousKeyValidUntil' => $this->previousKeyValidUntil?->format(\DateTimeInterface::ATOM),
            'previousKeyPrefix' => $this->previousKeyPrefix,
            'lastRotatedAt' => $this->lastRotatedAt->format(\DateTimeInterface::ATOM),
            'tokenVersion' => $this->tokenVersion,
            'newPlainText' => '[REDACTED]',
        ];
    }

    /**
     * @return array{newKeyPrefix: string, newKeyHash: string, previousKeyHash: string|null, previousKeyValidUntil: string|null, previousKeyPrefix: string|null, lastRotatedAt: string, tokenVersion: int, newPlainText: string}
     */
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    /**
     * @return array{newKeyPrefix: string, newKeyHash: string, previousKeyHash: string|null, previousKeyValidUntil: string|null, previousKeyPrefix: string|null, lastRotatedAt: string, tokenVersion: int, newPlainText: string}
     */
    public function __serialize(): array
    {
        return $this->__debugInfo();
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('Rotation must not be unserialized; plaintext is single-use.');
    }
}
