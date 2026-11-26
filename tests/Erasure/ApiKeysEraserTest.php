<?php

declare(strict_types=1);

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Events\CacheHit;
use Illuminate\Cache\Events\CacheMissed;
use Illuminate\Cache\Events\KeyForgotten;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use Qiick\ApiKeys\Contracts\ApiKeyErasureRepositoryContract;
use Qiick\ApiKeys\Erasure\ApiKeysEraser;
use Qiick\ApiKeys\Events\SubjectErasedEvent;
use Qiick\ApiKeys\Tests\Support\ErasureTestCase;

require_once __DIR__.'/Support/ErasureFixture.php';
require_once __DIR__.'/Support/ErasurePerson.php';

it('clears owned credential caches quietly at the outer commit and preserves third-party credentials', function (): void {
    $fixture = require __DIR__.'/fixture.php';
    $subject = $fixture->makePerson();
    $other = $fixture->makePerson();
    $fixture->seed($subject, null);
    $fixture->seed($other, null);

    $otherKey = DB::table('api_keys')->where('uuid', $other->publicIds[1]);
    $otherKey->update(['created_by' => $subject->userId, 'revoked_by' => $subject->userId, 'revocation_note' => $subject->identifiers[0]]);

    $leaseKey = 'api-keys:legacy-format-warning:'.$subject->publicIds[1].':'.ErasureTestCase::LEGACY_CUTOFF.':lease';
    expect(Cache::lock($leaseKey, 900)->get())->toBeTrue();

    Event::fake([SubjectErasedEvent::class, CacheHit::class, CacheMissed::class, KeyForgotten::class]);
    $eraser = app(ApiKeysEraser::class);
    $connection = DB::connection();
    $connection->beginTransaction();
    $report = $eraser->erase($subject->userId, $subject->userPublicId, 'delete', $subject->publicIds, $subject->identifiers);

    expect($report->toArray())->toBe([
        'package' => 'qiick/laravel-api-keys',
        'mode' => 'delete',
        'dry_run' => false,
        'stores' => [
            'api_keys' => ['deleted' => 1, 'anonymised' => 1, 'kept' => 0, 'reason' => null],
            'cache:'.config('api-keys.cache_store') => ['deleted' => 6, 'anonymised' => 0, 'kept' => 0, 'reason' => null],
            'cache:array' => ['deleted' => 1, 'anonymised' => 0, 'kept' => 0, 'reason' => null],
        ],
    ])->and($report->changed())->toBe(9);
    Event::assertNotDispatched(SubjectErasedEvent::class);
    expect(Cache::lock($leaseKey, 900)->get())->toBeFalse();

    $connection->commit();

    Event::assertDispatchedOnce(SubjectErasedEvent::class);
    Event::assertNotDispatched(CacheHit::class);
    Event::assertNotDispatched(CacheMissed::class);
    Event::assertNotDispatched(KeyForgotten::class);
    expect(Cache::lock($leaseKey, 900)->get())->toBeTrue();
    expect(DB::table('users')->where('id', $subject->userId)->exists())->toBeTrue()
        ->and($otherKey->first())->created_by->toBeNull()->revoked_by->toBeNull()->revocation_note->toBeNull();

    foreach ($fixture->cacheKeys($other) as $store => $keys) {
        foreach ($keys as $key) {
            expect(Cache::store($store)->has($key))->toBeTrue();
        }
    }
});

it('uses the default attempt store when none is configured and counts cache values once', function (): void {
    $store = Mockery::mock(ArrayStore::class)->makePartial();
    Cache::extend('erasure-shared', fn () => Cache::repository($store));
    config()->set('cache.stores.erasure-shared', ['driver' => 'erasure-shared']);
    config()->set('cache.default', 'erasure-shared');
    config()->set('api-keys.cache_store', null);
    $fixture = require __DIR__.'/fixture.php';
    $subject = $fixture->makePerson();
    $fixture->seed($subject, null);
    $marker = 'api-keys:legacy-format-warning:'.$subject->publicIds[1].':'.ErasureTestCase::LEGACY_CUTOFF;
    $store->shouldReceive('forget')->with($marker)->once()->passthru();

    $eraser = app(ApiKeysEraser::class);
    $report = $eraser->erase(...$subject->arguments('anonymise'));

    expect($report->stores)->toBe([
        'api_keys' => ['deleted' => 0, 'anonymised' => 1, 'kept' => 0, 'reason' => null],
        'cache:erasure-shared' => ['deleted' => 7, 'anonymised' => 0, 'kept' => 0, 'reason' => null],
    ])->and($store->all())->toBe([]);
});

it('finds warning markers by snapshot UUID even after the credential row has gone', function (): void {
    $keyPublicId = (string) Str::uuid();
    $marker = 'api-keys:legacy-format-warning:'.$keyPublicId.':'.ErasureTestCase::LEGACY_CUTOFF;
    Cache::forever($marker, 'sent');

    $report = app(ApiKeysEraser::class)->erase('erasure-user', (string) Str::uuid(), 'delete', [$keyPublicId]);

    expect($report->changed())->toBe(1)->and(Cache::has($marker))->toBeFalse();
});

it('reports both stores when there is no data and legacy warnings are disabled', function (): void {
    config()->set('api-keys.legacy.accept_until', null);

    $report = app(ApiKeysEraser::class)->erase('erasure-user', (string) Str::uuid(), 'delete');

    expect(array_keys($report->stores))->toBe(['api_keys', 'cache:'.config('api-keys.cache_store'), 'cache:array'])
        ->and($report->changed())->toBe(0);
});

it('retries an incomplete cache cleanup using the original identities from the product snapshot', function (): void {
    $subjectPublicId = (string) Str::uuid();
    $keyPublicId = (string) Str::uuid();
    $leaseKey = 'api-keys:legacy-format-warning:'.$keyPublicId.':'.ErasureTestCase::LEGACY_CUTOFF;
    Cache::forever($leaseKey, 'sent');

    $repository = Mockery::mock(ApiKeyErasureRepositoryContract::class);
    $repository->shouldReceive('connection')->andReturn(DB::connection());
    $repository->shouldReceive('eraseForUser')->twice()->andReturn(
        ['deleted' => 1, 'anonymised' => 0, 'keyIdsByPublicId' => [$keyPublicId => 71]],
        ['deleted' => 0, 'anonymised' => 0, 'keyIdsByPublicId' => [$keyPublicId => 71]],
    );

    $store = Mockery::mock(ArrayStore::class)->makePartial();
    $store->put('api-key:71', 1, 600);
    $store->shouldReceive('forget')->with('api-key:71')->once()->andReturnFalse();
    $store->shouldReceive('forget')->with('api-key:71')->passthru();
    Cache::extend('erasure-retry', fn () => Cache::repository($store));
    config()->set('cache.stores.erasure-retry', ['driver' => 'erasure-retry']);
    config()->set('api-keys.cache_store', 'erasure-retry');
    Event::fake([SubjectErasedEvent::class]);

    $eraser = new ApiKeysEraser($repository);
    $erase = fn () => $eraser->erase('erasure-user', $subjectPublicId, 'delete');

    expect($erase)->toThrow(RuntimeException::class, 'API key erasure could not forget its cache entries.');
    Event::assertNotDispatched(SubjectErasedEvent::class);
    expect($store->get('api-key:71'))->toBe(1);
    expect($erase()->changed())->toBe(2)
        ->and($store->get('api-key:71'))->toBeNull()
        ->and(Cache::has($leaseKey))->toBeFalse();
    Event::assertDispatchedOnce(SubjectErasedEvent::class);
});

it('redacts database and cache read failures before returning them to the product', function (bool $isDatabaseFailure): void {
    $fixture = require __DIR__.'/fixture.php';
    $subject = $fixture->makePerson();
    $fixture->seed($subject, null);

    if ($isDatabaseFailure) {
        DB::connection()->beforeExecuting(static function (string $query) use ($subject): void {
            if (str_starts_with($query, 'delete')) {
                throw new QueryException('api_keys_erasure', $query, [$subject->userId], new RuntimeException($subject->identifiers[0]));
            }
        });
    } else {
        $store = Mockery::mock(ArrayStore::class);
        $store->shouldReceive('many')->andThrow(new RuntimeException($subject->userPublicId));
        Cache::extend('erasure-unavailable', fn () => Cache::repository($store));
        config()->set('cache.stores.erasure-unavailable', ['driver' => 'erasure-unavailable']);
        config()->set('api-keys.cache_store', 'erasure-unavailable');
    }

    $erase = fn () => app(ApiKeysEraser::class)->erase(...$subject->arguments('delete'));
    $message = $isDatabaseFailure
        ? 'API key erasure could not complete its database operation.'
        : 'API key erasure could not inspect its cache entries.';

    expect($erase)->toThrow(function (RuntimeException $exception) use ($message): void {
        expect($exception->getMessage())->toBe($message)->and($exception->getPrevious())->toBeNull();
    })->and(DB::table('api_keys')->where('uuid', $subject->publicIds[1])->exists())->toBeTrue();
})->with([true, false]);
