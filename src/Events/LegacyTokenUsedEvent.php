<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Events;

use Qiick\ApiKeys\AuthenticationResult;

/**
 * @api Fired by products after successful authentication of a legacy token.
 *
 * Payload never includes the plaintext token. Dispatch only when
 * {@see AuthenticationResult::$legacyMatcherClass} is non-null —
 * never on format/hash miss.
 */
final class LegacyTokenUsedEvent
{
    /**
     * @param  class-string  $matcherClass
     */
    public function __construct(
        public string $keyPrefix,
        public string $matcherClass,
        public \DateTimeImmutable $acceptUntil,
    ) {}
}
