<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Canonical token parts after a successful parse (never logged as a whole).
 */
final readonly class ParsedToken implements \JsonSerializable
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

    /**
     * @return array{productPrefix: string, environment: string, publicId: string, secret: string, keyPrefix: string}
     */
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    /**
     * @return array{productPrefix: string, environment: string, publicId: string, secret: string, keyPrefix: string}
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
        throw new \LogicException('ParsedToken must not be unserialized; the secret is single-use.');
    }
}
