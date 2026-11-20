<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Tests\Support;

use DateTimeImmutable;
use Qiick\ApiKeys\LegacyTokenMatcher;

/**
 * Test double for TokenCodec legacy prefix lookup (not shipped to apps).
 */
final class RecordingLegacyTokenMatcher implements LegacyTokenMatcher
{
    public int $prefixOfCalls = 0;

    public function __construct(
        private ?string $prefix,
        private DateTimeImmutable $acceptUntil,
        private int $secretLength = 31,
        private bool $forceAccepting = true,
    ) {}

    public function prefixOf(#[\SensitiveParameter] string $token): ?string
    {
        $this->prefixOfCalls++;

        if ($this->prefix === null) {
            return null;
        }

        return str_starts_with($token, $this->prefix) ? $this->prefix : null;
    }

    public function isAccepting(DateTimeImmutable $now): bool
    {
        if (! $this->forceAccepting) {
            return false;
        }

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

    /**
     * Product early-stop: isAccepting false while acceptUntil is still in the future.
     */
    public function withoutAccepting(): self
    {
        return new self($this->prefix, $this->acceptUntil, $this->secretLength, forceAccepting: false);
    }
}
