<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Plaintext returned once; never stored; redacted in debug output.
 */
final readonly class GeneratedToken
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
}
