<?php

declare(strict_types=1);

use Qiick\ApiKeys\UsageRecorder;

mutates(UsageRecorder::class);

function recorder(): UsageRecorder
{
    return new UsageRecorder;
}

it('always records when lastUsedAt is null', function (): void {
    $now = new DateTimeImmutable('2026-01-15 12:00:00');

    expect(recorder()->shouldRecord($now, null, null, '203.0.113.10'))->toBeTrue();
});

it('records when the throttle window has fully elapsed (>= boundary)', function (): void {
    $now = new DateTimeImmutable('2026-01-15 12:00:00');
    $last = $now->modify('-60 seconds');

    expect(recorder()->shouldRecord($now, $last, '203.0.113.10', '203.0.113.10', 60, false))->toBeTrue()
        ->and(recorder()->shouldRecord($now, $now->modify('-59 seconds'), '203.0.113.10', '203.0.113.10', 60, false))->toBeFalse();
});

it('bypasses throttle only when enabled and the IP actually changed', function (): void {
    $now = new DateTimeImmutable('2026-01-15 12:00:00');
    $last = $now->modify('-1 second');

    expect(recorder()->shouldRecord($now, $last, '203.0.113.10', '198.51.100.1', 60, true))->toBeTrue()
        ->and(recorder()->shouldRecord($now, $last, '203.0.113.10', '203.0.113.10', 60, true))->toBeFalse()
        ->and(recorder()->shouldRecord($now, $last, '203.0.113.10', '198.51.100.1', 60, false))->toBeFalse()
        ->and(recorder()->shouldRecord($now, $last, '203.0.113.10', null, 60, true))->toBeFalse();
});

it('uses the default throttle of 60 seconds and bypass-on-IP-change true', function (): void {
    $now = new DateTimeImmutable('2026-01-15 12:00:00');
    $last = $now->modify('-60 seconds');

    // Defaults: throttle 60, bypass true — elapsed boundary records even without IP change.
    expect(recorder()->shouldRecord($now, $last, '203.0.113.10', '203.0.113.10'))->toBeTrue()
        ->and(recorder()->shouldRecord($now, $now->modify('-59 seconds'), '203.0.113.10', '203.0.113.10'))->toBeFalse()
        ->and(recorder()->shouldRecord($now, $now->modify('-1 second'), 'a', 'b'))->toBeTrue();
});

it('records on first use even when current IP is null (early return is load-bearing)', function (): void {
    $now = new DateTimeImmutable('2026-01-15 12:00:00');

    // Without the lastUsedAt===null early return, null IP skips bypass and then
    // dereferences null lastUsedAt — this assertion kills RemoveEarlyReturn.
    expect(recorder()->shouldRecord($now, null, null, null))->toBeTrue();
});
