<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\Contracts\RandomSource;

/**
 * @api Deterministic CSPRNG seam for issuance tests.
 *
 * Each call to bytes() consumes the next chunk from the seed stream (repeating
 * when exhausted). Same seed → same alphabet lengths from TokenCodec.
 */
final class FixedRandomSource implements RandomSource
{
    private int $offset = 0;

    public function __construct(private string $seed)
    {
        if ($this->seed === '') {
            throw new \InvalidArgumentException('FixedRandomSource seed must not be empty.');
        }
    }

    public function bytes(int $length): string
    {
        if ($length < 1) {
            throw new \InvalidArgumentException('Random byte length must be at least 1.');
        }

        $output = '';
        $seedLength = strlen($this->seed);

        while (strlen($output) < $length) {
            $output .= $this->seed[$this->offset % $seedLength];
            $this->offset++;
        }

        return $output;
    }
}
