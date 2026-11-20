<?php

declare(strict_types=1);

use Qiick\ApiKeys\FailedAttemptLimiter;
use Qiick\ApiKeys\Testing\FakeAttemptLimiter;

mutates(FailedAttemptLimiter::class);

it('hits and trips the per-IP failed-attempt brake', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 2);

    expect($limiter->tooManyAttempts('203.0.113.10'))->toBeFalse();
    $limiter->hit('203.0.113.10');
    $limiter->hit('203.0.113.10');
    expect($limiter->tooManyAttempts('203.0.113.10'))->toBeTrue()
        ->and($inner->hitsFor('api-key-failures:203.0.113.10'))->toBe(2)
        ->and($limiter->maxPerMinute())->toBe(2);
});

it('disables when maxPerMinute is zero or negative', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 0);

    $limiter->hit('203.0.113.10');
    expect($limiter->tooManyAttempts('203.0.113.10'))->toBeFalse()
        ->and($inner->hitsFor('api-key-failures:203.0.113.10'))->toBe(0);
});
