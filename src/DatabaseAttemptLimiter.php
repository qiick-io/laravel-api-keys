<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\QueryException;
use Illuminate\Support\Carbon;
use Qiick\ApiKeys\Contracts\AttemptLimiter;

/**
 * @api {@see AttemptLimiter} on the product's `api_key_attempts` table, so the
 * package needs no Redis or Memcached.
 *
 * One row per bucket: `bucket` (primary key), `hits`, and `expires_at` (Unix
 * seconds); docs/reference-schema.md has the table. Windows are fixed from
 * their first hit, and a row whose `expires_at` has passed counts as missing
 * on every read. `api-keys:prune-attempts` deletes those rows.
 *
 * A hit is atomic across workers on SQLite, MySQL, MariaDB and PostgreSQL:
 * - insert-or-ignore creates the row if it is missing (the primary key
 *   settles a race between two first hits);
 * - one `UPDATE` adds the hit, or starts a new window on a stale row, under
 *   the row lock;
 * - the read-back runs in the same transaction, so it sees this worker's own
 *   count, not one that another worker has raised since.
 * The insert stays outside that transaction. On MySQL, an `INSERT IGNORE` of an
 * existing key holds a shared lock on the row until commit, and two
 * transactions that both hold it and then both `UPDATE` deadlock.
 *
 * Time is the app clock (`Carbon::now()`), as in {@see CacheAttemptLimiter}.
 * Workers must keep their clocks in sync (NTP).
 */
final class DatabaseAttemptLimiter implements AttemptLimiter
{
    public function __construct(
        private ConnectionInterface $connection,
        private string $table = 'api_key_attempts',
    ) {}

    public function table(): string
    {
        return $this->table;
    }

    public function hasTable(): bool
    {
        return $this->connection->getSchemaBuilder()->hasTable($this->table);
    }

    /**
     * @throws \InvalidArgumentException when the window is shorter than one second
     * @throws \RuntimeException when the table is missing, or the row vanished
     *                           between the insert and the update (a prune of a
     *                           stale row in that instant); the request fails closed
     */
    public function hit(string $key, int $decaySeconds = 60): int
    {
        if ($decaySeconds < 1) {
            throw new \InvalidArgumentException('An attempt window must last at least one second.');
        }

        return $this->onTable(function () use ($key, $decaySeconds): int {
            $now = Carbon::now()->getTimestamp();
            $windowEndsAt = $now + $decaySeconds;

            $this->connection->table($this->table)->insertOrIgnore([
                'bucket' => $key,
                'hits' => 0,
                'expires_at' => $windowEndsAt,
            ]);

            return $this->connection->transaction(function () use ($key, $now, $windowEndsAt): int {
                // Both values are integers from the clock, so inlining them is safe. Neither
                // CASE reads a column assigned before it, so MySQL's left-to-right SET order
                // gives the same result as the other engines.
                $this->connection->table($this->table)->where('bucket', $key)->update([
                    'hits' => $this->connection->raw("CASE WHEN expires_at <= {$now} THEN 1 ELSE hits + 1 END"),
                    'expires_at' => $this->connection->raw("CASE WHEN expires_at <= {$now} THEN {$windowEndsAt} ELSE expires_at END"),
                ]);

                $hits = $this->connection->table($this->table)->where('bucket', $key)->value('hits');

                return is_numeric($hits) ? (int) $hits : throw new \RuntimeException('The attempt counter vanished while it was counted.');
            });
        });
    }

    public function decrement(string $key): void
    {
        $this->onTable(fn (): int => $this->liveBucket($key)->where('hits', '>', 0)->decrement('hits'));
    }

    public function availableIn(string $key): int
    {
        return $this->onTable(function () use ($key): int {
            $windowEndsAt = $this->liveBucket($key)->value('expires_at');

            return is_numeric($windowEndsAt) ? (int) $windowEndsAt - Carbon::now()->getTimestamp() : 0;
        });
    }

    public function remaining(string $key, int $maxAttempts): int
    {
        return $this->onTable(function () use ($key, $maxAttempts): int {
            $hits = $this->liveBucket($key)->value('hits');

            return max(0, $maxAttempts - (is_numeric($hits) ? (int) $hits : 0));
        });
    }

    /**
     * Deletes the rows whose window has ended and returns how many. Safe to
     * run while requests are counted: a live window is never touched.
     */
    public function prune(): int
    {
        return $this->onTable(
            fn (): int => $this->connection->table($this->table)->where('expires_at', '<=', Carbon::now()->getTimestamp())->delete(),
        );
    }

    private function liveBucket(string $key): Builder
    {
        return $this->connection->table($this->table)
            ->where('bucket', $key)
            ->where('expires_at', '>', Carbon::now()->getTimestamp());
    }

    /**
     * A missing table is a deploy mistake, so it gets a message that says how
     * to fix it. Any other database error passes through unchanged. Either
     * way the authenticator answers 503: the brake is never skipped.
     *
     * @template TResult
     *
     * @param  callable(): TResult  $operation
     * @return TResult
     *
     * @throws \RuntimeException when the table is missing
     */
    private function onTable(callable $operation): mixed
    {
        try {
            return $operation();
        } catch (QueryException $exception) {
            if ($this->hasTable()) {
                throw $exception;
            }

            throw new \RuntimeException(
                "The {$this->table} table is missing: create it as docs/reference-schema.md describes.",
                previous: $exception,
            );
        }
    }
}
