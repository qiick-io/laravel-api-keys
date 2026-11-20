<?php

declare(strict_types=1);

use Qiick\ApiKeys\FailedAttemptLimiter;
use Qiick\ApiKeys\Testing\FakeAttemptLimiter;

mutates(FailedAttemptLimiter::class);

it('hits and trips the per-IP failed-attempt brake for IPv4 /32', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 2);

    expect($limiter->bucketKey('203.0.113.10'))->toBe('api-key-failures:v4:203.0.113.10')
        ->and($limiter->tooManyAttempts('203.0.113.10'))->toBeFalse();

    $limiter->hit('203.0.113.10');
    $limiter->hit('203.0.113.10');

    expect($limiter->tooManyAttempts('203.0.113.10'))->toBeTrue()
        ->and($inner->hitsFor('api-key-failures:v4:203.0.113.10'))->toBe(2)
        ->and($limiter->maxPerMinute())->toBe(2)
        ->and($limiter->availableIn('203.0.113.10'))->toBe(60);
});

it('buckets IPv6 addresses by /64', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 1);

    $first = '2001:db8:1:2::10';
    $second = '2001:db8:1:2::99';
    $otherNetwork = '2001:db8:1:3::10';

    expect($limiter->bucketKey($first))->toBe($limiter->bucketKey($second))
        ->and($limiter->bucketKey($first))->not->toBe($limiter->bucketKey($otherNetwork));

    $limiter->hit($first);
    expect($limiter->tooManyAttempts($second))->toBeTrue()
        ->and($limiter->tooManyAttempts($otherNetwork))->toBeFalse();
});

it('unwraps IPv4-mapped IPv6 into the matching IPv4 bucket', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 1);

    $mapped = '::ffff:203.0.113.10';
    $dotted = '203.0.113.10';

    expect($limiter->bucketKey($mapped))->toBe('api-key-failures:v4:203.0.113.10')
        ->and($limiter->bucketKey($mapped))->toBe($limiter->bucketKey($dotted))
        ->and($limiter->bucketKey($mapped))->not->toStartWith('api-key-failures:v6:');

    $limiter->hit($mapped);
    expect($limiter->tooManyAttempts($dotted))->toBeTrue()
        ->and($inner->hitsFor('api-key-failures:v4:203.0.113.10'))->toBe(1)
        ->and($inner->hitsFor('api-key-failures:v6:::'))->toBe(0);
});

it('skips the brake for null, empty, or unparseable client IPs', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 1);

    expect($limiter->bucketKey(null))->toBeNull()
        ->and($limiter->bucketKey(''))->toBeNull()
        ->and($limiter->bucketKey('not-an-ip'))->toBeNull();

    $limiter->hit(null);
    $limiter->hit('');
    $limiter->hit('not-an-ip');

    expect($limiter->tooManyAttempts(null))->toBeFalse()
        ->and($limiter->tooManyAttempts(''))->toBeFalse()
        ->and($limiter->availableIn(null))->toBe(0)
        ->and($inner->hitsFor('api-key-failures:'))->toBe(0);
});

it('disables when maxPerMinute is zero or negative', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 0);

    $limiter->hit('203.0.113.10');
    expect($limiter->tooManyAttempts('203.0.113.10'))->toBeFalse()
        ->and($inner->hitsFor('api-key-failures:v4:203.0.113.10'))->toBe(0);

    $negative = new FailedAttemptLimiter($inner, maxPerMinute: -1);
    $negative->hit('203.0.113.10');
    expect($negative->tooManyAttempts('203.0.113.10'))->toBeFalse();
});

it('defaults maxPerMinute to 20 and uses the exact v6 bucket prefix', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner);

    expect($limiter->maxPerMinute())->toBe(20);

    for ($i = 0; $i < 20; $i++) {
        $limiter->hit('203.0.113.10');
    }
    expect($limiter->tooManyAttempts('203.0.113.10'))->toBeTrue();

    // Same /64, different /72 — must share the /64 bucket (substr length 8).
    $a = '2001:db8:1:2:0000::1';
    $b = '2001:db8:1:2:0001::1';
    expect($limiter->bucketKey($a))->toBe('api-key-failures:v6:2001:db8:1:2::')
        ->and($limiter->bucketKey($b))->toBe('api-key-failures:v6:2001:db8:1:2::');
});
