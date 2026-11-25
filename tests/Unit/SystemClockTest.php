<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Facade;
use Qiick\ApiKeys\SystemClock;

mutates(SystemClock::class);

afterEach(function (): void {
    Carbon::setTestNow();
    Date::useDefault();
});

it('follows Laravel\'s test clock, so Carbon::setTestNow() needs no Clock binding', function (): void {
    Carbon::setTestNow('2030-06-01 08:30:15.250000');

    expect((new SystemClock)->now()->format('Y-m-d H:i:s.u e'))->toBe('2030-06-01 08:30:15.250000 UTC');
});

it('follows the Date facade a product configured', function (): void {
    Date::useCallable(fn (Carbon $now): Carbon => $now->setDate(2031, 2, 3)->setTime(4, 5, 6));

    expect((new SystemClock)->now()->format('Y-m-d H:i:s'))->toBe('2031-02-03 04:05:06');
});

it('always answers in UTC, whatever zone Laravel\'s clock is in', function (): void {
    Carbon::setTestNow(Carbon::parse('2030-06-01 10:30:00', 'Europe/Rome'));

    $now = (new SystemClock)->now();

    expect($now->getTimezone()->getName())->toBe('UTC')
        ->and($now->format('H:i'))->toBe('08:30');
});

it('reads the system clock in UTC when Laravel is not booted', function (): void {
    $application = Facade::getFacadeApplication();
    Facade::setFacadeApplication(null);
    // Must not leak into the clock outside Laravel.
    Carbon::setTestNow('2030-06-01 08:30:00');

    try {
        $before = time();
        $now = (new SystemClock)->now();
        $after = time();
    } finally {
        Facade::setFacadeApplication($application);
    }

    expect($now->getTimezone()->getName())->toBe('UTC')
        ->and($now->getTimestamp())->toBeGreaterThanOrEqual($before)->toBeLessThanOrEqual($after);
});
