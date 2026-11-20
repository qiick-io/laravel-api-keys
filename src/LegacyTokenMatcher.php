<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Product registers explicitly. Boot fails if a matcher is registered without acceptUntil.
 *
 * {@see prefixOf} must also recognise a bare stored `key_prefix` (the prefix alone,
 * with no secret) so {@see TokenCodec::isValidKeyPrefix} / rotation can migrate
 * legacy rows. Declare {@see secretLength} as the expected secret remainder for
 * that shape (Externa `ek_` = 31); the package enforces a floor of 20.
 */
interface LegacyTokenMatcher
{
    public function prefixOf(#[\SensitiveParameter] string $token): ?string;

    public function isAccepting(\DateTimeImmutable $now): bool;

    public function acceptUntil(): \DateTimeImmutable;

    /**
     * Expected secret character count after the stored prefix (e.g. 31 for ek_).
     */
    public function secretLength(): int;
}
