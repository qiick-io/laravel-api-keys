<?php

declare(strict_types=1);

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Schema;
use Qiick\ApiKeys\CacheAttemptLimiter;
use Qiick\ApiKeys\Contracts\AttemptLimiter;
use Qiick\ApiKeys\Tests\Support\RacedRefundCacheRepository;

mutates(CacheAttemptLimiter::class);

/**
 * The same behaviour on every cache store Testbench can run in process: array,
 * file, and database (in-memory SQLite). Real Redis and Memcached run in
 * tests/Database/CacheAttemptLimiterStoreTest, and the cross-process races in
 * tests/Database/CacheAttemptLimiterConcurrencyTest.
 */
function limiterCacheStore(string $store): Repository
{
    config(['cache.stores.file.path' => sys_get_temp_dir().'/api-keys-limiter-test']);

    if ($store === 'database' && ! Schema::hasTable('cache')) {
        // Laravel's own cache table (its create_cache_table migration).
        Schema::create('cache', function (Blueprint $table): void {
            $table->string('key')->primary();
            $table->mediumText('value');
            $table->integer('expiration')->index();
        });
    }

    $repository = Cache::store($store);
    $repository->flush();

    return $repository;
}

function cacheLimiter(string $store): CacheAttemptLimiter
{
    return new CacheAttemptLimiter(limiterCacheStore($store));
}

dataset('in-process stores', ['array', 'file', 'database']);

it('opens a 60-second window by default and reports nothing for an unknown bucket', function (string $store): void {
    $this->freezeTime();
    $limiter = cacheLimiter($store);

    expect($limiter->availableIn('unknown'))->toBe(0)
        ->and($limiter->remaining('unknown', 3))->toBe(3)
        ->and($limiter->hit('bucket'))->toBe(1)
        ->and($limiter->availableIn('bucket'))->toBe(60)
        ->and($limiter->hit('bucket'))->toBe(2)
        ->and($limiter->hit('bucket'))->toBe(3)
        ->and($limiter->remaining('bucket', 5))->toBe(2)
        ->and($limiter->remaining('bucket', 2))->toBe(0);
})->with('in-process stores');

it('keeps the window its first hit opened, then starts a new one once it expires', function (string $store): void {
    $this->freezeTime();
    $limiter = cacheLimiter($store);

    expect($limiter->hit('bucket', 60))->toBe(1);

    $this->travel(30)->seconds();

    expect($limiter->hit('bucket', 600))->toBe(2)
        ->and($limiter->availableIn('bucket'))->toBe(30);

    $this->travel(31)->seconds();

    expect($limiter->availableIn('bucket'))->toBe(0)
        ->and($limiter->remaining('bucket', 5))->toBe(5)
        ->and($limiter->hit('bucket', 10))->toBe(1)
        ->and($limiter->availableIn('bucket'))->toBe(10);
})->with('in-process stores');

it('keeps buckets apart', function (string $store): void {
    $limiter = cacheLimiter($store);

    $limiter->hit('first');
    $limiter->hit('first');

    expect($limiter->hit('second'))->toBe(1)
        ->and($limiter->remaining('first', 5))->toBe(3);
})->with('in-process stores');

it('takes back an attempt, never below zero', function (string $store): void {
    $limiter = cacheLimiter($store);

    $limiter->hit('bucket', 60);
    $limiter->hit('bucket', 60);
    $limiter->decrement('bucket');

    expect($limiter->remaining('bucket', 5))->toBe(4);

    $limiter->decrement('bucket');
    $limiter->decrement('bucket');

    expect($limiter->remaining('bucket', 5))->toBe(5)
        ->and($limiter->hit('bucket', 60))->toBe(1);
})->with('in-process stores');

it('never brings back a missing or expired counter, so a long window keeps its length', function (string $store): void {
    $this->freezeTime();
    $limiter = cacheLimiter($store);

    $limiter->decrement('missing');

    expect(Cache::store($store)->get('missing'))->toBeNull();

    $limiter->hit('day', 10);
    $this->travel(11)->seconds();
    $limiter->decrement('day');

    // A decrement on the expired counter would have opened a 60-second window at -1.
    expect($limiter->hit('day', 86_400))->toBe(1)
        ->and($limiter->availableIn('day'))->toBe(86_400);
})->with('in-process stores');

it('keeps counting after a refund races another worker below zero', function (string $store, string $race): void {
    $this->freezeTime();
    $limiter = new CacheAttemptLimiter(new RacedRefundCacheRepository(limiterCacheStore($store), $race));

    $limiter->hit('bucket', 60);
    $limiter->decrement('bucket');

    // Left at -1, the next hit would count 0 and fail closed for good.
    expect($limiter->hit('bucket', 60))->toBe(1)
        ->and($limiter->hit('bucket', 60))->toBe(2)
        ->and($limiter->availableIn('bucket'))->toBe(60);
})->with([
    'array, expired' => ['array', 'expired'],
    'array, concurrent' => ['array', 'concurrent'],
    'file, expired' => ['file', 'expired'],
    'file, concurrent' => ['file', 'concurrent'],
    'database, concurrent' => ['database', 'concurrent'],
]);

it('refuses a window shorter than one second', function (int $decaySeconds): void {
    expect(fn () => cacheLimiter('array')->hit('bucket', $decaySeconds))
        ->toThrow(InvalidArgumentException::class, 'An attempt window must last at least one second.');
})->with([0, -1]);

it('accepts a one-second window', function (): void {
    $this->freezeTime();
    $limiter = cacheLimiter('array');

    expect($limiter->hit('bucket', 1))->toBe(1)
        ->and($limiter->availableIn('bucket'))->toBe(1);
});

it('fails closed when the store does not count the attempt', function (): void {
    config(['cache.stores.none' => ['driver' => 'null']]);
    $limiter = new CacheAttemptLimiter(Cache::store('none'));

    expect(fn () => $limiter->hit('bucket'))
        ->toThrow(RuntimeException::class, 'The cache store did not count the attempt.');
});

it('is the AttemptLimiter the package binds by default', function (): void {
    config(['cache.default' => 'array']);

    expect(app(AttemptLimiter::class))->toBeInstanceOf(CacheAttemptLimiter::class);
});
