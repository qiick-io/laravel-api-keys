<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Events;

/**
 * @api Fired when a key is marked exposed (scanner or manual).
 *
 * Never carries secret material.
 */
final class ApiKeyExposedEvent
{
    public function __construct(
        public string $apiKeyId,
        public string $exposureSource,
        public \DateTimeImmutable $exposedAt,
    ) {}
}
