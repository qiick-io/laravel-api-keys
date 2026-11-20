<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Events;

use Qiick\ApiKeys\TokenCodec;

/**
 * @api Fired by products when a legacy matcher accepted a presented token.
 *
 * Payload never includes the plaintext token. Products typically dispatch this
 * after {@see TokenCodec::legacyMatcherFor} returns a matcher.
 */
final class LegacyTokenUsed
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
