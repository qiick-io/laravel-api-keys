<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Tests\Support;

use Illuminate\Cache\Repository;

/**
 * A cache repository on which a refund races another worker, for the two
 * cases the attempt limiter must survive between `attempts() > 0` and
 * `decrement()`:
 *
 * - `expired`: the window ends in between, so the decrement finds no counter;
 * - `concurrent`: another refund already took the counter down from the 1 that
 *   this refund read, so this one decrements 0.
 *
 * Either way most stores leave the counter below zero.
 */
final class RacedRefundCacheRepository extends Repository
{
    public function __construct(
        private Repository $inner,
        private string $race,
    ) {
        parent::__construct($inner->getStore());
    }

    /**
     * @param  string  $key
     * @param  mixed  $value
     */
    public function decrement($key, $value = 1): int|bool
    {
        if ($this->race === 'expired') {
            $this->inner->forget($key);
        } else {
            $this->inner->getStore()->decrement($key, 1);
        }

        return $this->inner->getStore()->decrement($key, $value);
    }
}
