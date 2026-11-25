<?php

declare(strict_types=1);

use Illuminate\Cache\MemcachedConnector;
use Illuminate\Cache\MemcachedStore;
use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\RedisStore;
use Illuminate\Cache\Repository;
use Illuminate\Container\Container;
use Illuminate\Redis\RedisManager;
use Qiick\ApiKeys\CacheAttemptLimiter;

mutates(CacheAttemptLimiter::class);

/**
 * In-process checks of CacheAttemptLimiter on real Redis and Memcached, so the
 * mutation gate sees every store branch. Runs when API_KEYS_LIMITER_STORE is
 * redis, memcached or both; the cross-process races live in
 * CacheAttemptLimiterConcurrencyTest.
 *
 * @return list<string>
 */
function limiterStoresUnderTest(): array
{
    return match (getenv('API_KEYS_LIMITER_STORE')) {
        'redis' => ['redis'],
        'memcached' => ['memcached'],
        'both' => ['redis', 'memcached'],
        default => [],
    };
}

function realLimiterStore(string $storeName): Repository
{
    $store = match ($storeName) {
        'redis' => new RedisStore(
            new RedisManager(new Container, 'phpredis', [
                'default' => ['host' => '127.0.0.1', 'port' => 6379, 'database' => 15],
            ]),
            'api-keys-limiter-store-test:',
        ),
        'memcached' => new MemcachedStore(
            (new MemcachedConnector)->connect([['host' => '127.0.0.1', 'port' => 11211, 'weight' => 100]]),
            'api-keys-limiter-store-test:',
        ),
    };

    $repository = new Repository($store);
    $repository->forget('bucket');
    $repository->forget('bucket:timer');

    return $repository;
}

dataset('limiter stores', function (): array {
    $stores = limiterStoresUnderTest();

    return $stores === [] ? ['no store configured' => [null]] : array_combine($stores, array_map(fn (string $store): array => [$store], $stores));
});

beforeEach(function (): void {
    if (limiterStoresUnderTest() === []) {
        $this->markTestSkipped('Set API_KEYS_LIMITER_STORE=redis|memcached|both to test a real store.');
    }
});

it('counts hits and reports the remaining attempts and the time left in the window', function (?string $storeName): void {
    $limiter = new CacheAttemptLimiter(new RateLimiter(realLimiterStore((string) $storeName)));

    expect($limiter->hit('bucket', 60))->toBe(1)
        ->and($limiter->hit('bucket', 60))->toBe(2)
        ->and($limiter->remaining('bucket', 5))->toBe(3)
        ->and($limiter->availableIn('bucket'))->toBeInt()->toBeGreaterThan(55)->toBeLessThanOrEqual(60);
})->with('limiter stores');

it('never decrements below zero, and ignores a counter that does not exist', function (?string $storeName): void {
    $limiter = new CacheAttemptLimiter(new RateLimiter(realLimiterStore((string) $storeName)));

    $limiter->decrement('bucket');
    expect($limiter->remaining('bucket', 5))->toBe(5);

    $limiter->hit('bucket', 60);
    $limiter->hit('bucket', 60);
    $limiter->decrement('bucket');

    expect($limiter->remaining('bucket', 5))->toBe(4);

    $limiter->decrement('bucket');
    $limiter->decrement('bucket');

    expect($limiter->remaining('bucket', 5))->toBe(5)
        ->and($limiter->hit('bucket', 60))->toBe(1);
})->with('limiter stores');

it('lets a window expire and starts a fresh one', function (?string $storeName): void {
    $limiter = new CacheAttemptLimiter(new RateLimiter(realLimiterStore((string) $storeName)));

    $limiter->hit('bucket', 1);
    usleep(2_100_000);
    $limiter->decrement('bucket');

    expect($limiter->availableIn('bucket'))->toBe(0)
        ->and($limiter->remaining('bucket', 5))->toBe(5)
        ->and($limiter->hit('bucket', 60))->toBe(1);
})->with('limiter stores');

it('keeps counting a window longer than 30 days', function (?string $storeName): void {
    $limiter = new CacheAttemptLimiter(new RateLimiter(realLimiterStore((string) $storeName)));

    expect($limiter->hit('bucket', 2_678_400))->toBe(1)
        ->and($limiter->hit('bucket', 2_678_400))->toBe(2)
        ->and($limiter->availableIn('bucket'))->toBeGreaterThan(2_678_000);
})->with('limiter stores');

it('refuses a window shorter than one second instead of opening the limit', function (?string $storeName): void {
    $limiter = new CacheAttemptLimiter(new RateLimiter(realLimiterStore((string) $storeName)));

    expect(fn () => $limiter->hit('bucket', 0))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $limiter->hit('bucket', -5))->toThrow(InvalidArgumentException::class);
})->with('limiter stores');

it('opens a 60-second window by default, reports nothing for an unknown bucket and never a negative remainder', function (?string $storeName): void {
    $limiter = new CacheAttemptLimiter(new RateLimiter(realLimiterStore((string) $storeName)));

    expect($limiter->availableIn('bucket'))->toBe(0)
        ->and($limiter->hit('bucket'))->toBe(1)
        ->and($limiter->availableIn('bucket'))->toBeGreaterThan(55)->toBeLessThanOrEqual(60)
        ->and($limiter->hit('bucket'))->toBe(2)
        ->and($limiter->hit('bucket'))->toBe(3)
        ->and($limiter->remaining('bucket', 2))->toBe(0);
})->with('limiter stores');

it('keeps counting a window one second past 30 days', function (?string $storeName): void {
    $limiter = new CacheAttemptLimiter(new RateLimiter(realLimiterStore((string) $storeName)));

    expect($limiter->hit('bucket', 2_592_001))->toBe(1)
        ->and($limiter->hit('bucket', 2_592_001))->toBe(2);
})->with('limiter stores');

it('fails loudly when memcached cannot be reached', function (): void {
    if (! in_array('memcached', limiterStoresUnderTest(), true)) {
        $this->markTestSkipped('Runs with the memcached store.');
    }

    $unreachable = new Repository(new MemcachedStore(
        (new MemcachedConnector)->connect([['host' => '127.0.0.1', 'port' => 1, 'weight' => 100]]),
        'api-keys-limiter-store-test:',
    ));

    try {
        (new CacheAttemptLimiter(new RateLimiter($unreachable)))->hit('bucket');
        $this->fail('expected the unreachable server to be reported');
    } catch (RuntimeException $exception) {
        // Laravel's RateLimiter reads Memcached's `false` as 0: the limiter must not admit that.
        expect($exception->getMessage())->toBe('The cache store did not count the attempt.');
    }
});
