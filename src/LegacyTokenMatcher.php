<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Product registers explicitly. Boot fails if a matcher is registered without acceptUntil.
 */
interface LegacyTokenMatcher
{
    public function prefixOf(#[\SensitiveParameter] string $token): ?string;

    public function isAccepting(\DateTimeImmutable $now): bool;

    public function acceptUntil(): \DateTimeImmutable;
}
