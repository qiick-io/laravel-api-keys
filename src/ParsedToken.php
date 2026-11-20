<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Canonical token parts after a successful parse (never logged as a whole).
 */
final readonly class ParsedToken
{
    public function __construct(
        public string $productPrefix,
        public TokenEnvironment $environment,
        public string $publicId,
        public string $secret,
        public string $keyPrefix,
    ) {}

    /**
     * @return array{productPrefix: string, environment: string, publicId: string, secret: string, keyPrefix: string}
     */
    public function __debugInfo(): array
    {
        return [
            'productPrefix' => $this->productPrefix,
            'environment' => $this->environment->value,
            'publicId' => $this->publicId,
            'secret' => '[REDACTED]',
            'keyPrefix' => $this->keyPrefix,
        ];
    }
}
