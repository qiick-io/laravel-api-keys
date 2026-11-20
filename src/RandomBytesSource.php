<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Qiick\ApiKeys\Contracts\RandomSource;

/** @api Production CSPRNG: random_bytes. */
final class RandomBytesSource implements RandomSource
{
    public function bytes(int $length): string
    {
        if ($length < 1) {
            throw new \InvalidArgumentException('Random byte length must be at least 1.');
        }

        return random_bytes($length);
    }
}
