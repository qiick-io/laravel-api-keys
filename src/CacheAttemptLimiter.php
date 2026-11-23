<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\MemcachedStore;
use Illuminate\Cache\RedisStore;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Redis\Connections\PhpRedisConnection;
use Illuminate\Redis\Connections\PredisConnection;
use Illuminate\Support\Carbon;
use Qiick\ApiKeys\Contracts\AttemptLimiter;

/**
 * @api {@see AttemptLimiter} on a Laravel cache store, atomic across workers.
 *
 * Laravel's own `RateLimiter` is not enough here: its `increment()` falls back
 * to a non-atomic `put()` whenever a counter has to be recreated, and the
 * database store's `add()` / `increment()` are not atomic at all. Under
 * parallel requests that let 36 guesses through a limit of 10. This class
 * talks to the store primitives that are atomic and refuses every other store:
 *
 * - Redis: one Lua script per operation. `INCR` plus `EXPIRE` on the first hit
 *   opens the window, so a counter can never outlive it; `DECR` only runs on an
 *   existing counter above zero.
 * - Memcached: `add` (atomic create-if-missing with the window as TTL) then
 *   `increment`; `decrement` is a no-op on a missing key and floors at zero.
 * - Array: a single process cannot race; for tests and local development.
 *
 * Windows last at least one second (shorter ones throw) and are fixed from
 * their first hit. A decrement that arrives after the window expired finds no counter and does nothing, so counts never go negative.
 */
final class CacheAttemptLimiter implements AttemptLimiter
{
    private const string REDIS_HIT = <<<'LUA'
        local hits = redis.call('INCR', KEYS[1])
        if hits == 1 then
            redis.call('EXPIRE', KEYS[1], ARGV[1])
        end
        return hits
        LUA;

    private const string REDIS_DECREMENT = <<<'LUA'
        local hits = tonumber(redis.call('GET', KEYS[1]))
        if hits and hits > 0 then
            redis.call('DECR', KEYS[1])
        end
        return 0
        LUA;

    /** One of `redis`, `memcached`, `array`: decided once, so every call takes the same path. */
    private string $storeKind;

    /**
     * @throws \InvalidArgumentException when the store cannot count atomically
     */
    public function __construct(
        private Repository $cache,
    ) {
        $store = $cache->getStore();

        $this->storeKind = match (true) {
            $store instanceof RedisStore => 'redis',
            $store instanceof MemcachedStore => 'memcached',
            $store instanceof ArrayStore => 'array',
            default => throw new \InvalidArgumentException(
                'CacheAttemptLimiter needs a redis, memcached or array cache store; '
                .$store::class.' cannot increment atomically across workers.',
            ),
        };
    }

    /**
     * @throws \InvalidArgumentException when the window is shorter than one second:
     *                                   Redis would expire the counter at once and open the limit
     */
    public function hit(string $key, int $decaySeconds = 60): int
    {
        if ($decaySeconds < 1) {
            throw new \InvalidArgumentException('An attempt window must last at least one second.');
        }

        if ($this->storeKind === 'redis') {
            // Redis reads the window from the counter's own TTL.
            return $this->countedHits($this->redisEval(self::REDIS_HIT, $key, $decaySeconds));
        }

        $this->cache->add($key.':timer', Carbon::now()->getTimestamp() + $decaySeconds, $decaySeconds);

        if ($this->storeKind === 'memcached') {
            return $this->memcachedHit($key, $decaySeconds);
        }

        $this->cache->add($key, 0, $decaySeconds);

        return $this->countedHits($this->cache->increment($key));
    }

    public function decrement(string $key): void
    {
        if ($this->storeKind === 'redis') {
            $this->redisEval(self::REDIS_DECREMENT, $key);

            return;
        }

        if ($this->storeKind === 'memcached') {
            // Memcached refuses to decrement a missing key and never goes below zero.
            $this->memcachedStore()->getMemcached()->decrement($this->memcachedStore()->getPrefix().$key);

            return;
        }

        if ($this->hits($key) > 0) {
            $this->cache->decrement($key);
        }
    }

    public function availableIn(string $key): int
    {
        if ($this->storeKind === 'redis') {
            // TTL is -2 for a missing counter; a counter without TTL cannot exist (see REDIS_HIT).
            return max(0, $this->countedHits($this->redisConnection()->ttl($this->redisStore()->getPrefix().$key)));
        }

        // Stores may hand numbers back as numeric strings.
        $windowEndsAt = $this->cache->get($key.':timer');

        return is_numeric($windowEndsAt) ? max(0, (int) $windowEndsAt - Carbon::now()->getTimestamp()) : 0;
    }

    public function remaining(string $key, int $maxAttempts): int
    {
        return max(0, $maxAttempts - $this->hits($key));
    }

    private function hits(string $key): int
    {
        $hits = $this->cache->get($key);

        return is_numeric($hits) ? (int) $hits : 0;
    }

    /**
     * @throws \RuntimeException when the store answers something other than a count
     */
    private function countedHits(mixed $reply): int
    {
        return is_int($reply) ? $reply : throw new \RuntimeException('The cache store did not return a count.');
    }

    private function redisEval(string $script, string $key, int ...$arguments): mixed
    {
        return $this->redisConnection()->eval($script, 1, $this->redisStore()->getPrefix().$key, ...$arguments);
    }

    /**
     * Both Laravel Redis clients take `eval($script, $numberOfKeys, ...$keysThenArguments)`
     * and apply the connection prefix to the keys, as Laravel's own cache locks rely on.
     */
    private function redisConnection(): PhpRedisConnection|PredisConnection
    {
        /** @var PhpRedisConnection|PredisConnection $connection */
        $connection = $this->redisStore()->connection();

        return $connection;
    }

    private function redisStore(): RedisStore
    {
        /** @var RedisStore $store */
        $store = $this->cache->getStore();

        return $store;
    }

    private function memcachedStore(): MemcachedStore
    {
        /** @var MemcachedStore $store */
        $store = $this->cache->getStore();

        return $store;
    }

    /**
     * `add` creates the counter with the window as its TTL, atomically; if the
     * window expires between `add` and `increment`, the increment fails and
     * the pair is retried once, so a counter never exists without a TTL.
     *
     * @throws \RuntimeException when memcached refuses both attempts (server unreachable)
     */
    private function memcachedHit(string $key, int $decaySeconds): int
    {
        $memcached = $this->memcachedStore()->getMemcached();
        $prefixedKey = $this->memcachedStore()->getPrefix().$key;
        // Memcached reads an expiry above 30 days as a Unix timestamp, not a duration.
        // Equivalent mutants: at exactly 30 days both forms name the same instant.
        $expiry = $decaySeconds > 2_592_000 ? Carbon::now()->getTimestamp() + $decaySeconds : $decaySeconds; // @pest-mutate-ignore: GreaterToGreaterOrEqual,DecrementInteger

        // Equivalent mutant: the second attempt only runs if the window expires between add and increment.
        foreach ([1, 2] as $attempt) { // @pest-mutate-ignore: RemoveArrayItem
            $memcached->add($prefixedKey, 0, $expiry);
            $hits = $memcached->increment($prefixedKey);

            if (is_int($hits)) {
                return $hits;
            }
        }

        throw new \RuntimeException('Memcached could not count an attempt: '.$memcached->getResultMessage());
    }
}
