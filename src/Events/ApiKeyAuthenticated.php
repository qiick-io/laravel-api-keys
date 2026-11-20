<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Events;

use Qiick\ApiKeys\ApiKeyAuthenticator;

/**
 * @api Fired by products after a successful {@see ApiKeyAuthenticator} call.
 *
 * Payload never includes the plaintext token.
 */
final class ApiKeyAuthenticated
{
    public function __construct(
        public string|int $apiKeyId,
        public string $keyPrefix,
        public bool $usedPreviousSecret,
        public ?string $clientIp,
    ) {}
}
