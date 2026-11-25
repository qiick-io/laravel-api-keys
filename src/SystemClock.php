<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Facade;
use Qiick\ApiKeys\Contracts\Clock;

/**
 * @api Production clock: "now" in UTC.
 *
 * Inside a booted Laravel app it reads Laravel's clock (`Date::now()`), so
 * `Carbon::setTestNow()`, `travel()` and a product's `Date` configuration move
 * expiry, grace and lease checks without binding another {@see Clock}.
 * Outside Laravel it reads the system clock.
 */
final class SystemClock implements Clock
{
    public function now(): \DateTimeImmutable
    {
        $utc = new \DateTimeZone('UTC');

        if (Facade::getFacadeApplication() === null) {
            return new \DateTimeImmutable('now', $utc);
        }

        return \DateTimeImmutable::createFromInterface(Date::now())->setTimezone($utc);
    }
}
