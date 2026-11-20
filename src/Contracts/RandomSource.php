<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

/**
 * @api CSPRNG seam; production uses random_bytes.
 */
interface RandomSource
{
    public function bytes(int $length): string;
}
