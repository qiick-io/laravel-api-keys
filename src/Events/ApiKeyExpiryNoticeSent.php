<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Events;

/**
 * @api Fired after an expiry notice is sent and `expiry_notified_at` is stamped.
 *
 * Never carries secret material.
 */
final class ApiKeyExpiryNoticeSent
{
    public function __construct(
        public string $apiKeyId,
        public \DateTimeImmutable $expiresAt,
        public \DateTimeImmutable $notifiedAt,
    ) {}
}
