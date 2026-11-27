<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Events;

/**
 * @api Fired after a legacy-format T−90 warning is sent (N2).
 *
 * Never carries secret material.
 */
final class ApiKeyLegacyFormatWarningSentEvent
{
    public function __construct(
        public string $apiKeyId,
        public \DateTimeImmutable $acceptUntil,
        public \DateTimeImmutable $warnedAt,
    ) {}
}
