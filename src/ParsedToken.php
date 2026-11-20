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
}
