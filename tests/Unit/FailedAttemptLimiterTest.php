<?php

declare(strict_types=1);

use Qiick\ApiKeys\FailedAttemptLimiter;
use Qiick\ApiKeys\Testing\FakeAttemptLimiter;

mutates(FailedAttemptLimiter::class);

it('counts failed guesses per IPv4 /32 and blocks once the limit is reached', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 2);

    expect($limiter->bucketKey('203.0.113.10'))->toBe('api-key-failures:v4:203.0.113.10')
        ->and($limiter->isBlocked('203.0.113.10'))->toBeFalse()
        ->and($limiter->countFailure('203.0.113.10'))->toBeTrue()
        ->and($limiter->isBlocked('203.0.113.10'))->toBeFalse()
        ->and($limiter->countFailure('203.0.113.10'))->toBeTrue()
        ->and($limiter->isBlocked('203.0.113.10'))->toBeTrue()
        ->and($limiter->countFailure('203.0.113.10'))->toBeFalse()
        ->and($inner->hitsFor('api-key-failures:v4:203.0.113.10'))->toBe(3)
        ->and($inner->lastDecaySeconds['api-key-failures:v4:203.0.113.10'])->toBe(60)
        ->and($limiter->maxPerMinute())->toBe(2)
        ->and($limiter->availableIn('203.0.113.10'))->toBe(60);
});

it('only reads the bucket when checking whether it is blocked', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 1);

    foreach (range(1, 3) as $check) {
        expect($limiter->isBlocked('203.0.113.10'))->toBeFalse();
    }

    expect($inner->hitsFor('api-key-failures:v4:203.0.113.10'))->toBe(0);
});

it('buckets IPv6 addresses by /64', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 1);

    $first = '2001:db8:1:2::10';
    $second = '2001:db8:1:2::99';
    $otherNetwork = '2001:db8:1:3::10';

    expect($limiter->bucketKey($first))->toBe($limiter->bucketKey($second))
        ->and($limiter->bucketKey($first))->not->toBe($limiter->bucketKey($otherNetwork))
        ->and($limiter->countFailure($first))->toBeTrue()
        ->and($limiter->isBlocked($second))->toBeTrue()
        ->and($limiter->isBlocked($otherNetwork))->toBeFalse();
});

it('unwraps IPv4-mapped IPv6 into the matching IPv4 bucket', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 1);

    $mapped = '::ffff:203.0.113.10';
    $dotted = '203.0.113.10';

    expect($limiter->bucketKey($mapped))->toBe('api-key-failures:v4:203.0.113.10')
        ->and($limiter->bucketKey($mapped))->toBe($limiter->bucketKey($dotted))
        ->and($limiter->bucketKey($mapped))->not->toStartWith('api-key-failures:v6:')
        ->and($limiter->countFailure($mapped))->toBeTrue()
        ->and($limiter->isBlocked($dotted))->toBeTrue()
        ->and($inner->hitsFor('api-key-failures:v4:203.0.113.10'))->toBe(1)
        ->and($inner->hitsFor('api-key-failures:v6:::'))->toBe(0);
});

it('skips the brake for null, empty, or unparseable client IPs', function (?string $clientIp): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 1);

    expect($limiter->bucketKey($clientIp))->toBeNull()
        ->and($limiter->countFailure($clientIp))->toBeTrue()
        ->and($limiter->countFailure($clientIp))->toBeTrue()
        ->and($limiter->isBlocked($clientIp))->toBeFalse()
        ->and($limiter->availableIn($clientIp))->toBe(0)
        ->and($inner->hitsFor('api-key-failures:'))->toBe(0);
})->with([
    'null' => null,
    'empty' => '',
    'unparseable' => 'not-an-ip',
]);

it('disables when maxPerMinute is zero or negative', function (int $maxPerMinute): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: $maxPerMinute);

    expect($limiter->countFailure('203.0.113.10'))->toBeTrue()
        ->and($limiter->countFailure('203.0.113.10'))->toBeTrue()
        ->and($limiter->isBlocked('203.0.113.10'))->toBeFalse()
        ->and($inner->hitsFor('api-key-failures:v4:203.0.113.10'))->toBe(0);
})->with([0, -1]);

it('defaults maxPerMinute to 20 and uses the exact v6 bucket prefix', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner);

    expect($limiter->maxPerMinute())->toBe(20);

    foreach (range(1, 20) as $attempt) {
        expect($limiter->countFailure('203.0.113.10'))->toBeTrue();
    }

    expect($limiter->countFailure('203.0.113.10'))->toBeFalse();

    // Same /64, different /72 — must share the /64 bucket (substr length 8).
    $sameNetworkFirst = '2001:db8:1:2:0000::1';
    $sameNetworkSecond = '2001:db8:1:2:0001::1';
    expect($limiter->bucketKey($sameNetworkFirst))->toBe('api-key-failures:v6:2001:db8:1:2::')
        ->and($limiter->bucketKey($sameNetworkSecond))->toBe('api-key-failures:v6:2001:db8:1:2::');
});

it('can cap failures across a whole IPv6 /48 as a second tier', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 20, maxPerMinutePerIpv6Slash48: 2);

    expect($limiter->countFailure('2001:db8:1:1::1'))->toBeTrue()
        ->and($limiter->countFailure('2001:db8:1:2::1'))->toBeTrue()
        // A third /64 in the same /48 is already blocked, and one more guess goes over.
        ->and($limiter->isBlocked('2001:db8:1:3::1'))->toBeTrue()
        ->and($limiter->countFailure('2001:db8:1:3::1'))->toBeFalse()
        ->and($limiter->isBlocked('2001:db8:2:1::1'))->toBeFalse()
        ->and($inner->hitsFor('api-key-failures:v6-48:2001:db8:1::'))->toBe(3)
        // IPv4 has no second tier.
        ->and($limiter->countFailure('203.0.113.10'))->toBeTrue()
        ->and($limiter->isBlocked('203.0.113.10'))->toBeFalse();
});

it('leaves the /48 tier off by default', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 1);

    $limiter->countFailure('2001:db8:1:1::1');

    expect($limiter->isBlocked('2001:db8:1:2::1'))->toBeFalse()
        ->and($inner->hitsFor('api-key-failures:v6-48:2001:db8:1::'))->toBe(0);
});

it('keeps exactly 48 bits for the second tier and 64 for the first', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 5, maxPerMinutePerIpv6Slash48: 1);

    // These two /64s differ in the seventh byte, still inside one /48.
    expect($limiter->countFailure('2001:db8:1:100::1'))->toBeTrue()
        ->and($limiter->isBlocked('2001:db8:1:200::1'))->toBeTrue()
        // Same /64, differing in the ninth byte: one first-tier bucket.
        ->and($limiter->bucketKey('2001:db8:1:2:100::1'))->toBe($limiter->bucketKey('2001:db8:1:2:200::1'))
        ->and($limiter->bucketKey('2001:db8:1:2:100::1'))->toBe('api-key-failures:v6:2001:db8:1:2::');
});
