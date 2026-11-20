<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Tests\Support;

use DateTimeImmutable;
use Qiick\ApiKeys\LegacyTokenMatcher;

/**
 * Test/README fixture for a product-owned legacy matcher (not shipped in src/).
 *
 * Real Externa shape (design / ApiKey.php): `ek_` + 9 alnum + **31** alnum secret.
 * Also recognises a bare stored prefix so rotation can migrate the row.
 */
final class RegexLegacyTokenMatcher implements LegacyTokenMatcher
{
    private const int SECRET_LENGTH = 31;

    /**
     * @param  non-empty-string  $pattern  Must capture named group `prefix`
     * @param  non-empty-string|null  $barePrefixPattern  Optional pattern that
     *                                                    matches a stored key_prefix alone (no secret) for rotation.
     */
    public function __construct(
        private string $pattern,
        private DateTimeImmutable $acceptUntil,
        private ?string $barePrefixPattern = null,
        private int $secretLength = self::SECRET_LENGTH,
    ) {}

    public static function externaEkStyle(DateTimeImmutable $acceptUntil): self
    {
        return new self(
            pattern: '/^(?<prefix>ek_[A-Za-z0-9]{9})[A-Za-z0-9]{31}$/D',
            acceptUntil: $acceptUntil,
            barePrefixPattern: '/^(?<prefix>ek_[A-Za-z0-9]{9})$/D',
            secretLength: self::SECRET_LENGTH,
        );
    }

    public function prefixOf(#[\SensitiveParameter] string $token): ?string
    {
        if ($this->barePrefixPattern !== null
            && preg_match($this->barePrefixPattern, $token, $bare) === 1
        ) {
            $prefix = $bare['prefix'] ?? null;

            return is_string($prefix) && $prefix !== '' ? $prefix : null;
        }

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

    public function secretLength(): int
    {
        return $this->secretLength;
    }
}
