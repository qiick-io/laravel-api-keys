<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Qiick\ApiKeys\CacheAttemptLimiter;
use Qiick\ApiKeys\Contracts\AttemptLimiter;

mutates(CacheAttemptLimiter::class);

/**
 * Store-independent behaviour on the array store; the cross-process races run
 * against real Redis and Memcached in tests/Database.
 */
it('refuses cache stores that cannot count atomically across workers', function (string $store): void {
    config(['cache.stores.file.path' => sys_get_temp_dir()]);

    $storeClass = get_class(Cache::store($store)->getStore());

    expect(fn () => new CacheAttemptLimiter(Cache::store($store)))
        ->toThrow(
            InvalidArgumentException::class,
            'CacheAttemptLimiter needs a redis, memcached or array cache store; '.$storeClass.' cannot increment atomically across workers.',
        );
})->with(['database', 'file']);

it('opens a 60-second window by default and reports nothing for an unknown bucket', function (): void {
    $limiter = new CacheAttemptLimiter(Cache::store('array'));

    expect($limiter->availableIn('unknown'))->toBe(0)
        ->and($limiter->hit('bucket'))->toBe(1)
        ->and($limiter->availableIn('bucket'))->toBe(60)
        ->and($limiter->hit('bucket'))->toBe(2)
        ->and($limiter->hit('bucket'))->toBe(3)
        ->and($limiter->remaining('bucket', 2))->toBe(0);
});

it('counts hits in a window that its first hit opens', function (): void {
    $limiter = new CacheAttemptLimiter(Cache::store('array'));

    expect($limiter->hit('bucket', 60))->toBe(1)
        ->and($limiter->hit('bucket', 60))->toBe(2)
        ->and($limiter->remaining('bucket', 5))->toBe(3)
        ->and($limiter->availableIn('bucket'))->toBe(60);

    $this->travel(30)->seconds();
    $limiter->hit('bucket', 60);

    expect($limiter->availableIn('bucket'))->toBe(30);

    $this->travel(31)->seconds();

    expect($limiter->remaining('bucket', 5))->toBe(5)
        ->and($limiter->availableIn('bucket'))->toBe(0)
        ->and($limiter->hit('bucket', 60))->toBe(1);
});

it('never decrements below zero or brings back an expired counter', function (): void {
    $limiter = new CacheAttemptLimiter(Cache::store('array'));

    $limiter->decrement('bucket');
    expect($limiter->remaining('bucket', 5))->toBe(5);

    $limiter->hit('bucket', 10);
    $limiter->decrement('bucket');
    $limiter->decrement('bucket');
    expect($limiter->hit('bucket', 10))->toBe(1);

    $this->travel(11)->seconds();
    $limiter->decrement('bucket');

    expect(Cache::store('array')->get('bucket'))->toBeNull()
        ->and($limiter->hit('bucket', 10))->toBe(1);
});

it('is the AttemptLimiter the package binds by default', function (): void {
    config(['cache.default' => 'array']);

    expect(app(AttemptLimiter::class))->toBeInstanceOf(CacheAttemptLimiter::class);
});
