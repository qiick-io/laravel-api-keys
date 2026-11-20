<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

/**
 * @api Injectable clock for deterministic tests.
 */
interface Clock
{
    public function now(): \DateTimeImmutable;
}
