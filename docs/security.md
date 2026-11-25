# Attempt limits: Laravel's RateLimiter on the product's cache store

Decision of 2026-11-25 (#58, #59), by the maintainer: the per-key rate limits
and the failed-attempt brake count with Laravel's own
`Illuminate\Cache\RateLimiter`, on whichever cache store the product picks
(`api-keys.cache_store`, default store when null). The package adds no store
code of its own: no Lua scripts, no Memcached calls, no attempt table. This
replaces the 0.3.0-beta.1 `CacheAttemptLimiter`, which accepted only Redis and
Memcached.

## The race we accept

`RateLimiter::increment()` creates a counter with `add()`, increments it, and
when the increment returns 1 without having created the key, it resets the
counter with `put()`. Increments by other workers in that instant are lost,
so a burst at the start of a window can admit a few more attempts than the
limit. It happens at most once per window, and the lost increments are only
those in flight during that gap: with 50 parallel guesses against a limit of
10, local runs admitted between 10 and 13.

Each extra attempt is one more guess at a key with at least 128 bits of
entropy, so the brake's purpose (slow down guessing, refuse floods) still
holds. The cross-process tests in
`tests/Database/CacheAttemptLimiterConcurrencyTest.php` hold every store to:

- at least the limit and less than twice the limit admitted per burst;
- at most one reset per window: a second burst in the same window admits nothing;
- the next attempt after a burst is always refused.

## Where the package still fails closed

- The authenticator counts first and compares the returned count with the
  limit; it never checks and then counts in two steps.
- A hit that returns a count below 1 means the store did not count: an
  unreachable Memcached or the null store, where Laravel casts `false` to 0.
  `CacheAttemptLimiter::hit()` throws and the authenticator answers
  `503 service_unavailable` instead of admitting the request.
- `CacheAttemptLimiter::decrement()` only takes back a live counter above zero,
  through the cache repository's `decrement()`. `RateLimiter::decrement()` is an
  `increment()` by -1: Memcached refuses a negative offset (the refund would be
  lost), and on an expired counter it would create one at -1 with a 60-second
  window, cutting a day or month bucket short.
- Any exception from the store (Redis down, database locked) becomes a
  `503 service_unavailable`, reported to the exception handler. The limits are
  never skipped.

## Stores

| Store | Across workers | `api-keys:check` |
| --- | --- | --- |
| Redis, Memcached, DynamoDB | Atomic increments | Passes |
| Database on MySQL or PostgreSQL | Atomic: `lockForUpdate()` inside a transaction | Passes |
| Database on SQLite | Atomic only with `transaction_mode => 'IMMEDIATE'` (read by Laravel on PHP 8.4 and later) and a `busy_timeout` on the connection. Without them, parallel workers get `database is locked` and those requests answer 503 (fail closed). | Passes |
| File | **Not atomic:** `FileStore::increment()` reads, adds and writes back without a lock, so parallel workers on one server can let more attempts through than the limits | Warns |
| Array | Per process: tests only | Warns outside the `testing` environment |
| Null | Keeps nothing: the limits and the brake would be off | **Fails** |

For production, use Redis, Memcached, DynamoDB, or the database store on MySQL
or PostgreSQL. The choice stays the product's: only the null store fails the
check.
