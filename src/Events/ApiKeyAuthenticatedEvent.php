<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Events;

use Qiick\ApiKeys\ApiKeyAuthenticator;

/**
 * @api Fired by products after a successful {@see ApiKeyAuthenticator} call.
 *
 * Payload never includes the plaintext token. `$apiKeyId` is the public UUID.
 */
final class ApiKeyAuthenticatedEvent
{
    public function __construct(
        public string $apiKeyId,
        public string $keyPrefix,
        public bool $usedPreviousSecret,
        public ?string $clientIp,
    ) {}
}
