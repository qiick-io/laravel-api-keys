<?php

declare(strict_types=1);

/**
 * One "request" of the real-store concurrency test, run as its own PHP process
 * so that parallel workers race on the shared cache exactly like PHP-FPM
 * workers do. Prints 1 when the attempt was admitted, 0 when refused.
 *
 * Usage: php attempt-limiter-worker.php <store> <operation> <ip-or-key> <max> <start-at>
 * Stores: redis and memcached (CacheAttemptLimiter); sqlite, mysql, mariadb and
 * pgsql (DatabaseAttemptLimiter, on the databases the CI smoke job starts).
 * Operations on the failed-attempt brake for an IP: guess (a failed guess) and
 * request / slow-request (a key that authenticates).
 * Operations on a raw counter key: hit (give the attempt back when over max),
 * hit-short (hit with a one-second window), decrement, forget, and count
 * (prints the stored value, or "missing"). setup (re)creates the database table.
 */

use Illuminate\Cache\MemcachedConnector;
use Illuminate\Cache\MemcachedStore;
use Illuminate\Cache\RedisStore;
use Illuminate\Cache\Repository;
use Illuminate\Container\Container;
use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Redis\RedisManager;
use Qiick\ApiKeys\CacheAttemptLimiter;
use Qiick\ApiKeys\DatabaseAttemptLimiter;
use Qiick\ApiKeys\FailedAttemptLimiter;

require __DIR__.'/../../vendor/autoload.php';

[, $storeName, $operation, $key, $maxAttempts, $startAt] = $argv;

$database = in_array($storeName, ['sqlite', 'mysql', 'mariadb', 'pgsql'], true) ? attemptLimiterRaceDatabase($storeName) : null;

$store = $database !== null ? null : match ($storeName) {
    'redis' => new RedisStore(
        new RedisManager(new Container, 'phpredis', [
            'default' => [
                'host' => getenv('API_KEYS_REDIS_HOST') ?: '127.0.0.1',
                'port' => (int) (getenv('API_KEYS_REDIS_PORT') ?: 6379),
                'database' => 15,
            ],
        ]),
        'api-keys-limiter-test:',
    ),
    'memcached' => new MemcachedStore(
        (new MemcachedConnector)->connect([[
            'host' => getenv('API_KEYS_MEMCACHED_HOST') ?: '127.0.0.1',
            'port' => (int) (getenv('API_KEYS_MEMCACHED_PORT') ?: 11211),
            'weight' => 100,
        ]]),
        'api-keys-limiter-test:',
    ),
    default => throw new InvalidArgumentException('Unknown store '.$storeName),
};

$limiter = $database !== null ? new DatabaseAttemptLimiter($database) : new CacheAttemptLimiter(new Repository($store));

/**
 * The connection the CI databases smoke job starts for `$engine`. SQLite is a
 * shared file, since an in-memory database is private to each process.
 */
function attemptLimiterRaceDatabase(string $engine): ConnectionInterface
{
    $password = getenv('API_KEYS_CLAIM_PASSWORD') !== false ? (string) getenv('API_KEYS_CLAIM_PASSWORD') : 'password';
    $sqlitePath = sys_get_temp_dir().'/api-keys-limiter-race.sqlite';
    // Laravel resolves a missing SQLite file against base_path(), which a bare container lacks.
    touch($sqlitePath);
    $capsule = new Capsule;
    $capsule->addConnection(match ($engine) {
        'sqlite' => ['driver' => 'sqlite', 'database' => $sqlitePath, 'busy_timeout' => 10_000, 'journal_mode' => 'wal'],
        'mysql' => ['driver' => 'mysql', 'host' => '127.0.0.1', 'port' => 3306, 'database' => 'api_keys_claim', 'username' => 'root', 'password' => $password],
        'mariadb' => ['driver' => 'mariadb', 'host' => '127.0.0.1', 'port' => 3307, 'database' => 'api_keys_claim', 'username' => 'root', 'password' => $password],
        'pgsql' => ['driver' => 'pgsql', 'host' => '127.0.0.1', 'port' => 5432, 'database' => 'api_keys_claim', 'username' => 'postgres', 'password' => $password],
    });

    return $capsule->getConnection();
}

/**
 * The reference schema in docs/reference-schema.md.
 */
function createAttemptLimiterRaceTable(ConnectionInterface $database): void
{
    $schema = $database->getSchemaBuilder();
    $schema->dropIfExists('api_key_attempts');
    $schema->create('api_key_attempts', function (Blueprint $table): void {
        $table->string('bucket', 255)->primary();
        $table->unsignedInteger('hits')->default(0);
        $table->unsignedBigInteger('expires_at')->index();
    });
}

// Start together: every worker waits for the same instant before touching the store.
if ((float) $startAt > microtime(true)) {
    time_sleep_until((float) $startAt);
}

$maxAttempts = (int) $maxAttempts;

echo match ($operation) {
    // A failed guess, as ApiKeyAuthenticator handles it: refused early when the bucket is full, else counted.
    'guess' => (function () use ($limiter, $maxAttempts, $key): int {
        $brake = new FailedAttemptLimiter($limiter, $maxAttempts);

        return ! $brake->isBlocked($key) && $brake->countFailure($key) ? 1 : 0;
    })(),
    // A valid key whose verification (lookup, hash, authorizer) takes 0 or 200 ms; it is only read against the brake.
    'request', 'slow-request' => (function () use ($limiter, $maxAttempts, $key, $operation): int {
        $brake = new FailedAttemptLimiter($limiter, $maxAttempts);

        if ($brake->isBlocked($key)) {
            return 0;
        }

        usleep($operation === 'slow-request' ? 200_000 : 0);

        return $brake->isBlocked($key) ? 0 : 1;
    })(),
    'hit' => (function () use ($limiter, $maxAttempts, $key): int {
        if ($limiter->hit($key, 60) <= $maxAttempts) {
            return 1;
        }

        $limiter->decrement($key);

        return 0;
    })(),
    'hit-short' => $limiter->hit($key, 1),
    'decrement' => (function () use ($limiter, $key): int {
        $limiter->decrement($key);

        return 0;
    })(),
    'setup' => (function () use ($database): int {
        createAttemptLimiterRaceTable($database ?? throw new InvalidArgumentException('setup needs a database store'));

        return 1;
    })(),
    'forget' => $database !== null
        ? $database->table('api_key_attempts')->where('bucket', $key)->delete() >= 0
        : (int) $store->forget($key) & (int) $store->forget($key.':timer'),
    // A stale database row counts as missing, as it does for the limiter.
    'count' => is_numeric($counter = $database !== null
        ? $database->table('api_key_attempts')->where('bucket', $key)->where('expires_at', '>', time())->value('hits')
        : $store->get($key)) ? (string) (int) $counter : 'missing',
    default => throw new InvalidArgumentException('Unknown operation '.$operation),
};
