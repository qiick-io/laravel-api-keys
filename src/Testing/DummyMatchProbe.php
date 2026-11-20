<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\TokenCodec;

/**
 * @api Test seam for {@see TokenCodec::performDummyMatch}.
 */
final class DummyMatchProbe
{
    public int $calls = 0;

    public function record(): void
    {
        $this->calls++;
    }
}
