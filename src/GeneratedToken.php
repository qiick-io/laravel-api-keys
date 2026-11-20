<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Plaintext returned once; never stored; redacted in debug / JSON / serialize.
 *
 * Note: `(array) $token` and `var_export($token)` still expose public properties
 * (PHP has no hook for those). Prefer `__debugInfo` / `json_encode` / `serialize`,
 * or never pass a GeneratedToken into loggers that cast to array.
 */
final readonly class GeneratedToken implements \JsonSerializable
{
    public function __construct(
        #[\SensitiveParameter] public string $plainText,
        public string $keyPrefix,
        #[\SensitiveParameter] public string $keyHash,
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
