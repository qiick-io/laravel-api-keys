<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Qiick\ApiKeys\DatabaseAttemptLimiter;

mutates(DatabaseAttemptLimiter::class);

/**
 * Store-independent behaviour on the in-memory SQLite connection; the
 * cross-process races run on SQLite, MySQL, MariaDB and PostgreSQL in
 * tests/Database/CacheAttemptLimiterConcurrencyTest.
 */
function createAttemptsTable(string $table = 'api_key_attempts'): void
{
    // The reference schema in docs/reference-schema.md.
    Schema::create($table, function (Blueprint $blueprint): void {
        $blueprint->string('bucket', 255)->primary();
        $blueprint->unsignedInteger('hits')->default(0);
        $blueprint->unsignedBigInteger('expires_at')->index();
    });
}

function databaseLimiter(string $table = 'api_key_attempts'): DatabaseAttemptLimiter
{
    return new DatabaseAttemptLimiter(DB::connection(), $table);
}

beforeEach(function (): void {
    createAttemptsTable();
});

it('opens a 60-second window by default and reports nothing for an unknown bucket', function (): void {
    $this->freezeTime();
    $limiter = databaseLimiter();

    expect($limiter->availableIn('unknown'))->toBe(0)
        ->and($limiter->remaining('unknown', 3))->toBe(3)
        ->and($limiter->hit('bucket'))->toBe(1)
        ->and($limiter->availableIn('bucket'))->toBe(60)
        ->and($limiter->hit('bucket'))->toBe(2)
        ->and($limiter->hit('bucket'))->toBe(3)
        ->and($limiter->remaining('bucket', 5))->toBe(2)
        ->and($limiter->remaining('bucket', 2))->toBe(0);
});

it('keeps the window its first hit opened, then starts a new one once it expires', function (): void {
    $this->freezeTime();
    $limiter = databaseLimiter();

    expect($limiter->hit('bucket', 60))->toBe(1);

    $this->travel(30)->seconds();

    expect($limiter->hit('bucket', 600))->toBe(2)
        ->and($limiter->availableIn('bucket'))->toBe(30);

    $this->travel(29)->seconds();

    expect($limiter->availableIn('bucket'))->toBe(1)
        ->and($limiter->remaining('bucket', 5))->toBe(3);

    // The window ends exactly at its expiry second: the row is stale from then on.
    $this->travel(1)->seconds();

    expect($limiter->availableIn('bucket'))->toBe(0)
        ->and($limiter->remaining('bucket', 5))->toBe(5)
        ->and($limiter->hit('bucket', 10))->toBe(1)
        ->and($limiter->availableIn('bucket'))->toBe(10);
});

it('keeps buckets apart', function (): void {
    $limiter = databaseLimiter();

    $limiter->hit('first');
    $limiter->hit('first');

    expect($limiter->hit('second'))->toBe(1)
        ->and($limiter->remaining('first', 5))->toBe(3);
});

it('takes back an attempt, never below zero and never on a missing or expired bucket', function (): void {
    $this->freezeTime();
    $limiter = databaseLimiter();

    $limiter->hit('bucket', 60);
    $limiter->hit('bucket', 60);
    $limiter->decrement('bucket');

    expect($limiter->remaining('bucket', 5))->toBe(4);

    $limiter->decrement('bucket');
    $limiter->decrement('bucket');

    expect(DB::table('api_key_attempts')->where('bucket', 'bucket')->value('hits'))->toEqual(0);

    $limiter->decrement('missing');

    expect(DB::table('api_key_attempts')->where('bucket', 'missing')->exists())->toBeFalse();

    $limiter->hit('stale', 1);
    $limiter->hit('stale', 1);
    $this->travel(1)->seconds();
    $limiter->decrement('stale');

    expect(DB::table('api_key_attempts')->where('bucket', 'stale')->value('hits'))->toEqual(2)
        ->and($limiter->hit('stale', 1))->toBe(1);
});

it('refuses a window shorter than one second', function (int $decaySeconds): void {
    expect(fn () => databaseLimiter()->hit('bucket', $decaySeconds))
        ->toThrow(InvalidArgumentException::class, 'An attempt window must last at least one second.');
})->with([0, -1]);

it('accepts a one-second window', function (): void {
    $this->freezeTime();
    $limiter = databaseLimiter();

    expect($limiter->hit('bucket', 1))->toBe(1)
        ->and($limiter->availableIn('bucket'))->toBe(1);
});

it('prunes only the rows whose window has ended', function (): void {
    $this->freezeTime();
    $limiter = databaseLimiter();

    $limiter->hit('ended', 10);
    $limiter->hit('ending-now', 20);
    $limiter->hit('live', 21);
    $this->travel(20)->seconds();

    expect($limiter->prune())->toBe(2)
        ->and(DB::table('api_key_attempts')->pluck('bucket')->all())->toBe(['live'])
        ->and($limiter->prune())->toBe(0);
});

it('works on a table with another name', function (): void {
    createAttemptsTable('custom_attempts');
    $limiter = databaseLimiter('custom_attempts');

    expect($limiter->hit('bucket'))->toBe(1)
        ->and(DB::table('custom_attempts')->count())->toBe(1)
        ->and(DB::table('api_key_attempts')->count())->toBe(0);
});

it('names the table and the reference schema when the table is missing', function (string $operation): void {
    Schema::drop('api_key_attempts');
    $limiter = databaseLimiter();

    $call = match ($operation) {
        'hit' => fn () => $limiter->hit('bucket'),
        'decrement' => fn () => $limiter->decrement('bucket'),
        'availableIn' => fn () => $limiter->availableIn('bucket'),
        'remaining' => fn () => $limiter->remaining('bucket', 5),
        'prune' => fn () => $limiter->prune(),
    };

    expect($call)->toThrow(
        RuntimeException::class,
        'The api_key_attempts table is missing: create it as docs/reference-schema.md describes.',
    );
})->with(['hit', 'decrement', 'availableIn', 'remaining', 'prune']);

it('passes on other database errors unchanged', function (): void {
    Schema::drop('api_key_attempts');
    // The table exists, but without the hits column the limiter needs.
    Schema::create('api_key_attempts', function (Blueprint $blueprint): void {
        $blueprint->string('bucket', 255)->primary();
        $blueprint->unsignedBigInteger('expires_at');
    });

    expect(fn () => databaseLimiter()->hit('bucket'))
        ->toThrow(Illuminate\Database\QueryException::class);
});

it('reports whether its table exists', function (): void {
    expect(databaseLimiter()->hasTable())->toBeTrue()
        ->and(databaseLimiter('missing_attempts')->hasTable())->toBeFalse()
        ->and(databaseLimiter()->table())->toBe('api_key_attempts');
});
