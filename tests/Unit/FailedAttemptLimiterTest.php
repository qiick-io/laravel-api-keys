<?php

declare(strict_types=1);

use Qiick\ApiKeys\FailedAttemptLimiter;
use Qiick\ApiKeys\Testing\FakeAttemptLimiter;

mutates(FailedAttemptLimiter::class);

it('reserves up to maxPerMinute slots per IPv4 /32, then refuses without counting', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 2);

    expect($limiter->bucketKey('203.0.113.10'))->toBe('api-key-failures:v4:203.0.113.10')
        ->and($limiter->reserve('203.0.113.10'))->toBeTrue()
        ->and($limiter->reserve('203.0.113.10'))->toBeTrue()
        ->and($limiter->reserve('203.0.113.10'))->toBeFalse()
        ->and($inner->hitsFor('api-key-failures:v4:203.0.113.10'))->toBe(2)
        ->and($inner->lastDecaySeconds['api-key-failures:v4:203.0.113.10'])->toBe(60)
        ->and($limiter->maxPerMinute())->toBe(2)
        ->and($limiter->availableIn('203.0.113.10'))->toBe(60);
});

it('hands a released slot back so the next attempt is admitted', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 1);

    expect($limiter->reserve('203.0.113.10'))->toBeTrue();
    $inner->lastDecaySeconds = [];
    $limiter->release('203.0.113.10');

    expect($inner->hitsFor('api-key-failures:v4:203.0.113.10'))->toBe(0)
        ->and($inner->lastDecaySeconds)->toBe(['api-key-failures:v4:203.0.113.10' => 60])
        ->and($limiter->reserve('203.0.113.10'))->toBeTrue()
        ->and($limiter->reserve('203.0.113.10'))->toBeFalse();
});

it('buckets IPv6 addresses by /64', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 1);

    $first = '2001:db8:1:2::10';
    $second = '2001:db8:1:2::99';
    $otherNetwork = '2001:db8:1:3::10';

    expect($limiter->bucketKey($first))->toBe($limiter->bucketKey($second))
        ->and($limiter->bucketKey($first))->not->toBe($limiter->bucketKey($otherNetwork))
        ->and($limiter->reserve($first))->toBeTrue()
        ->and($limiter->reserve($second))->toBeFalse()
        ->and($limiter->reserve($otherNetwork))->toBeTrue();
});

it('unwraps IPv4-mapped IPv6 into the matching IPv4 bucket', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 1);

    $mapped = '::ffff:203.0.113.10';
    $dotted = '203.0.113.10';

    expect($limiter->bucketKey($mapped))->toBe('api-key-failures:v4:203.0.113.10')
        ->and($limiter->bucketKey($mapped))->toBe($limiter->bucketKey($dotted))
        ->and($limiter->bucketKey($mapped))->not->toStartWith('api-key-failures:v6:')
        ->and($limiter->reserve($mapped))->toBeTrue()
        ->and($limiter->reserve($dotted))->toBeFalse()
        ->and($inner->hitsFor('api-key-failures:v4:203.0.113.10'))->toBe(1)
        ->and($inner->hitsFor('api-key-failures:v6:::'))->toBe(0);
});

it('skips the brake for null, empty, or unparseable client IPs', function (?string $clientIp): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: 1);

    expect($limiter->bucketKey($clientIp))->toBeNull()
        ->and($limiter->reserve($clientIp))->toBeTrue()
        ->and($limiter->reserve($clientIp))->toBeTrue()
        ->and($limiter->availableIn($clientIp))->toBe(0)
        ->and($inner->hitsFor('api-key-failures:'))->toBe(0);

    $limiter->release($clientIp);

    expect($inner->hitsFor('api-key-failures:'))->toBe(0);
})->with([
    'null' => null,
    'empty' => '',
    'unparseable' => 'not-an-ip',
]);

it('disables when maxPerMinute is zero or negative', function (int $maxPerMinute): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner, maxPerMinute: $maxPerMinute);

    expect($limiter->reserve('203.0.113.10'))->toBeTrue()
        ->and($limiter->reserve('203.0.113.10'))->toBeTrue()
        ->and($inner->hitsFor('api-key-failures:v4:203.0.113.10'))->toBe(0);

    $limiter->release('203.0.113.10');

    expect($inner->hitsFor('api-key-failures:v4:203.0.113.10'))->toBe(0);
})->with([0, -1]);

it('defaults maxPerMinute to 20 and uses the exact v6 bucket prefix', function (): void {
    $inner = new FakeAttemptLimiter;
    $limiter = new FailedAttemptLimiter($inner);

    expect($limiter->maxPerMinute())->toBe(20);

    foreach (range(1, 20) as $attempt) {
        expect($limiter->reserve('203.0.113.10'))->toBeTrue();
    }

    expect($limiter->reserve('203.0.113.10'))->toBeFalse();

    // Same /64, different /72 — must share the /64 bucket (substr length 8).
    $sameNetworkFirst = '2001:db8:1:2:0000::1';
    $sameNetworkSecond = '2001:db8:1:2:0001::1';
    expect($limiter->bucketKey($sameNetworkFirst))->toBe('api-key-failures:v6:2001:db8:1:2::')
        ->and($limiter->bucketKey($sameNetworkSecond))->toBe('api-key-failures:v6:2001:db8:1:2::');
});
