<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Plaintext returned once; never stored; redacted in debug / JSON / serialize.
 */
final readonly class GeneratedToken implements \JsonSerializable
{
    public function __construct(
        public string $plainText,
        public string $keyPrefix,
        public string $keyHash,
    ) {}

    /**
     * @return array{keyPrefix: string, keyHash: string, plainText: string}
     */
    public function __debugInfo(): array
    {
        return [
            'keyPrefix' => $this->keyPrefix,
            'keyHash' => '[REDACTED]',
            'plainText' => '[REDACTED]',
        ];
    }

    /**
     * @return array{keyPrefix: string, keyHash: string, plainText: string}
     */
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    /**
     * @return array{keyPrefix: string, keyHash: string, plainText: string}
     */
    public function __serialize(): array
    {
        return $this->__debugInfo();
    }

    /**
     * @param  array{keyPrefix?: string, keyHash?: string, plainText?: string}  $data
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('GeneratedToken must not be unserialized; plaintext is single-use.');
    }
}
