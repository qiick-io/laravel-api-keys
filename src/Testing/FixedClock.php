<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\Contracts\Clock;

/** @api Test clock that returns a fixed instant. */
final class FixedClock implements Clock
{
    public function __construct(private \DateTimeImmutable $now) {}

    public function now(): \DateTimeImmutable
    {
        return $this->now;
    }

    public function set(\DateTimeImmutable $now): void
    {
        $this->now = $now;
    }
}
