<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Tests\Support;

use DateTimeImmutable;
use Qiick\ApiKeys\LegacyTokenMatcher;

/**
 * Test/README fixture for a product-owned legacy matcher (not shipped in src/).
 *
 * Example shape used in docs: Externa-style `ek_` + 9 alnum + 32 alnum secret
 * (remainder must be ≥ TokenCodec::SECRET_LENGTH so secret material cannot become key_prefix).
 * Products implement their own class when adopting the package.
 */
final class RegexLegacyTokenMatcher implements LegacyTokenMatcher
{
    /**
     * @param  non-empty-string  $pattern  Must capture named group `prefix`
     */
    public function __construct(
        private string $pattern,
        private DateTimeImmutable $acceptUntil,
    ) {}

    public static function externaEkStyle(DateTimeImmutable $acceptUntil): self
    {
        return new self('/^(?<prefix>ek_[A-Za-z0-9]{9})[A-Za-z0-9]{32}$/D', $acceptUntil);
    }

    public function prefixOf(#[\SensitiveParameter] string $token): ?string
    {
        if (preg_match($this->pattern, $token, $matches) !== 1) {
            return null;
        }

        $prefix = $matches['prefix'] ?? null;

        return is_string($prefix) && $prefix !== '' ? $prefix : null;
    }

    public function isAccepting(DateTimeImmutable $now): bool
    {
        return $now < $this->acceptUntil;
    }

    public function acceptUntil(): DateTimeImmutable
    {
        return $this->acceptUntil;
    }
}
