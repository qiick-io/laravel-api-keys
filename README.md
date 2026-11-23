<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/header-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset=".github/assets/header-light.svg">
    <img alt="laravel-api-keys: API keys for Laravel: tokens, scopes, RFC 6750" src=".github/assets/header-light.svg" width="100%">
  </picture>
</p>

# qiick/laravel-api-keys

> **Pre-release (0.x).** The public API may still change before 1.0.0: pin an exact version and read UPGRADING.md when you update.

Contract-only API key mechanics for qiick Laravel products: token issue/parse/verify,
fail-closed scopes, IP allowlist, RFC 6750 refusals in the fleet error format, rotation
grace, usage throttle, audit `api_key_id`, and test helpers.

**Products own** Eloquent models, migrations, permissions, scope enums, tenancy, and
HTTP middleware. This package does not register middleware; it does register
`api-keys:notify-expiring` (bind `ExpiryRecipientResolver`).

Part of the qiick fleet. Binding design:
`projects/qiick/packages/laravel-api-keys-design.md` in the knowledge base
(overlay: `decisions/2026-11-20-core-hardening.md`).

## Status

Pre-release `0.2.0`. Public APIs may change in any 0.x release; see
[UPGRADING.md](./UPGRADING.md). Pin an exact version. Packagist publish only
after Luca’s go.

## Requirements

- PHP `^8.3`
- Illuminate console / contracts / http / notifications / support `^12.0 \|\| ^13.0` (never `laravel/framework`)

## Install (when published)

```bash
composer require qiick/laravel-api-keys
php artisan vendor:publish --tag=api-keys-config
```

Set `API_KEYS_PRODUCT_PREFIX` (three-letter product code) before issuing tokens.

## Threat model (short)

| Topic | Contract |
| --- | --- |
| Proxies | `KeyContext::ip` / `ClientIp::from` MUST use `Request::ip()` only after `TrustProxies` is configured correctly. Never pass raw `X-Forwarded-For` / `X-Real-IP` from untrusted clients. |
| Enumeration | Format-miss and hash-miss return the **same** `401 invalid_token` body/headers. A dummy `hash_equals` runs when no candidates match. Pre-auth `FailedAttemptLimiter` is default-on in recipes. The public `key_prefix` is non-secret by design. |
| Failed-attempt brake | Buckets IPv4 by `/32` and IPv6 by `/64`. IPv4-mapped (`::ffff:a.b.c.d`) expands to dotted IPv4 before bucketing (same path as `IpAllowlist`). Null/empty/unparseable client IPs **skip** the brake (never share one bucket — that would lock out everyone behind a misconfigured proxy). Repository/infra exceptions are **not** counted. The brake counts each attempt **before** evaluating it (one atomic `AttemptLimiter::hit`), so concurrent guesses cannot exceed the cap; a successful or non-credential outcome hands its slot back. Shared egress / NAT: many clients behind one public IP share one bucket and can lock each other out; keep the recipe default **on** (20/min) and raise only with a clear threat model. Wire after `TrustProxies` so `KeyContext::ip` is the real client, not the LB. |
| Redaction | Presented tokens / Bearer values MUST NEVER appear in exception messages, JSON bodies, logs, telemetry, activity properties, or `__debugInfo`. |
| Scopes | Fail-closed: whitespace, wrong case, duplicates, or non-vocabulary values → empty set → `403 insufficient_scope` (never 401). |
| Audit | Activity under a key carries `api_key_id` = the key’s **public UUID** via `Audit::withApiKeyId` (never the internal bigint; lowercase UUID; rejects non-UUID, nil UUID, and a conflicting existing `api_key_id`). |
| Rotation | `RotationService::rotate` refuses revoked/expired keys, `oauth_grant` rows, and unknown prefixes; invalid/negative/above-max grace → 0 (max default 168h). Legacy prefixes migrate to a **fresh canonical** token; with grace > 0, `previous_key_prefix` keeps the old token findable through the normal window. Products **must** `lockForUpdate` and write every returned field unconditionally (including `previous_key_prefix`, `last_rotated_at`, `token_version`). |
| Expiry claim lease | `api-keys:notify-expiring` claims with `expiry_notice_claimed_at` (app/worker clock, not DB `NOW()`), then stamps `expiry_notified_at` after send. Default lease is **900** s (`API_KEYS_EXPIRY_CLAIM_LEASE_SECONDS`). Keep worker clocks on shared NTP UTC — skew can reclaim a live claim early. Keep the lease above worst-case send latency — an in-flight send longer than the lease can be reclaimed and produce a **double notice**. |

## Token shape

`{product}_{live|test}_{id}{secret}` — three-letter product prefix, 8-character
public id, 32-character secret (A–Za–z0–9). **Version 2** (default) appends a
6-character base62 CRC32 checksum (GitHub construction); version 1 stays
accepted. The row stores SHA-256 of the **full** plaintext (including checksum)
and records `token_version` / `hash_algorithm`.

Scanner regex (product prefix `ppp`):

```text
\bppp_(?:live|test)_[A-Za-z0-9]{40}(?:[A-Za-z0-9]{6})?\b
```

See [docs/reference-schema.md](./docs/reference-schema.md) for the full column list.

## Quotas (minute / day / month)

`rate_limit_per_minute`, `rate_limit_per_day`, and `rate_limit_per_month` are
enforced as **rolling windows** through Laravel's `RateLimiter` (decay 60 s /
86_400 s / 2_592_000 s). They are not calendar day or calendar month buckets.
Durable calendar quotas are LATER (standards review L4).

Limits hold under concurrency: the authenticator counts a request first with
`AttemptLimiter::hit()`, one atomic increment that returns the new count, and
refuses it when that count is over the limit (handing the attempt back with
`decrement()`). It never checks and then counts in two steps. Your adapter
must keep `hit()` atomic in a store every worker shares; Laravel's
`RateLimiter` does on Redis, Memcached and the database cache:

```php
final class RateLimiterAttemptLimiter implements AttemptLimiter
{
    public function __construct(private RateLimiter $rateLimiter) {}

    public function hit(string $key, int $decaySeconds = 60): int
    {
        return $this->rateLimiter->hit($key, $decaySeconds);
    }

    public function decrement(string $key, int $decaySeconds = 60): void
    {
        $this->rateLimiter->decrement($key, $decaySeconds);
    }

    public function availableIn(string $key): int
    {
        return $this->rateLimiter->availableIn($key);
    }

    public function remaining(string $key, int $maxAttempts): int
    {
        return $this->rateLimiter->remaining($key, $maxAttempts);
    }
}
```

## Expiry notices (claim lease)

`api-keys:notify-expiring` takes a CAS lease on `expiry_notice_claimed_at`
before sending, then stamps `expiry_notified_at` only after a successful send
(see `ExpiryNoticeClaimSql`). The lease cutoff is computed from the worker's
`Clock` (`$now`), not the database server clock.

Two operational risks (accepted as documented nits after #18):

1. **Clock skew.** Workers whose clocks disagree can reclaim a claim that is
   still live on another host. Run every notify worker on NTP-synced UTC.
2. **Send longer than the lease.** If delivery (mail, queue, webhook) exceeds
   `api-keys.expiry.claim_lease_seconds` (default **900**), another worker can
   win the CAS and send a second notice. Raise the lease, or keep sends short.

The legacy-format T−90 warning follows the same protocol with the same lease,
through `LegacyFormatWarningGate` (cache-backed by default): recipients are
resolved first, so a key with no recipient yet stays claimable; a failed send
releases the lease and the next run retries; a worker that dies mid-send
leaves a lease that lapses after `claim_lease_seconds`; a sent warning is
marked permanently and never repeats. The cache must be shared by all workers.

## Max key lifetime

`api-keys.max_lifetime_days` (`API_KEYS_MAX_LIFETIME_DAYS`) is enforced on
rotation by the default `ConfigLifetimePolicy`: `RotationService` refuses an
expiry later than now + that many days, or no expiry at all. Unset disables
it. Any other value must be a whole number >= 1; anything else (`0`, `30abc`,
`thirty`) fails at boot instead of being silently cast. Bind your own
`Contracts\LifetimePolicy` to replace the default, and call it from your
issuance code too: issuance is product-owned.

## Rotation (product persistence)

```php
DB::transaction(function () use ($key, $codec, $clock) {
    $locked = ApiKey::query()->whereKey($key->id)->lockForUpdate()->firstOrFail();
    $rotation = $rotationService->rotate($locked, $codec, $clock, config('api-keys.rotation_grace_hours'));

    // Write every field unconditionally (nulls when grace is 0;
    // previous_key_prefix is set when migrating a legacy prefix with grace).
    $locked->forceFill([
        'key_prefix' => $rotation->newKeyPrefix,
        'key_hash' => $rotation->newKeyHash,
        'previous_key_hash' => $rotation->previousKeyHash,
        'previous_key_valid_until' => $rotation->previousKeyValidUntil,
        'previous_key_prefix' => $rotation->previousKeyPrefix,
        'last_rotated_at' => $rotation->lastRotatedAt,
        'token_version' => $rotation->tokenVersion,
    ])->save();

    return $rotation; // show newPlainText once
});
```


## IP allowlist

`IpAllowlist::allows($ip, $stored)`: null/empty → allow all; non-list or
non-string entries → deny; zone-id client IPs (`fe80::1%eth0`) → deny.
IPv4-mapped forms (`::ffff:a.b.c.d`) expand to dotted IPv4 before
`IpUtils::checkIp` (mapped CIDR prefixes subtract 96); `::1` / `::` stay IPv6.
Prefix out of range (IPv4 0–32, IPv6 0–128) fails closed.
`ClientIp::from($request)` is `Request::ip()` only (configure TrustProxies).

## Scopes

Atoms match `^[a-z][a-z0-9-]*:(read|write)$` exactly (no trim/case-fold).
`ScopeSet::parseStored` is fail-closed: unknown, duplicate, whitespace, or
non-list input → empty set. `write` satisfies `read` on the same resource;
highest-per-resource drops a sibling `read` when `write` is present.

## Evaluation order

Extract the bearer first (`BearerTokenExtractor`: no trim; case-insensitive
`Bearer`), then call
`ApiKeyAuthenticator::authenticate($presentedToken, $context, $requiredScope)`:

1. Pre-auth `FailedAttemptLimiter` takes a slot (IPv4 `/32`, IPv6 `/64`; default
   20/min in recipes); only an `invalid_token` outcome keeps it →
2. Token format (`TokenCodec::prefixOf`, including legacy matchers when configured) →
3. Lookup by `key_prefix` / in-grace `previous_key_prefix` + `hash_equals`
   (dummy compare on miss; row `hash_algorithm`) →
4. Refuse `credential_kind = oauth_grant` as `401 invalid_token` →
5. Revoked / expired / unknown `token_version` →
6. Actor (`KeyAuthorizer::authorizeActor`) →
7. IP allowlist →
8. Request restrictions (`KeyRestrictions` / `RequestRestrictionsEvaluator`;
   malformed or denied → `403 request_not_allowed`; scheme/host compared
   case-insensitively). `new RequestRestrictions(...)` validates its own lists
   and throws `InvalidArgumentException` on a pattern the evaluator would not
   understand, so a hand-built instance cannot fail open →
9. Scopes: expand → owner ceiling via `scopesCreatorMayGrant` on the **record**
   (C1: the product decides ownerless/creator-less keys; write may demote to
   read) → collapse highest-per-resource → required scope / `authorizeScopes` →
10. Resource restrictions (`authorizeResources` when `restrictions.resources`
    is non-empty; denial → `403 request_not_allowed`) →
11. Per-key rate limits (`KeyAuthorizer::rateLimit()` list, else minute/day/month
    defaults from the row; `AttemptLimiter` buckets) →
12. Usage record (`UsageRecorder` throttle; `last_used_user_agent`; write
    failures are reported, not thrown).

### Wiring the failed-attempt brake (recipe default ON)

```php
$failedAttempts = new FailedAttemptLimiter(
    limiter: $attemptLimiter, // your RateLimiter adapter
    maxPerMinute: 20,         // ≤0 disables; leave ON unless you have a reason
);

$auth = new ApiKeyAuthenticator(
    // ...
    failedAttemptLimiter: $failedAttempts,
);
```

Pass `KeyContext::ip` from `ClientIp::from($request)` only after `TrustProxies` is correct.
Clients behind CGNAT / shared office egress share one IPv4 bucket — tune `maxPerMinute`
up only if false lockouts outweigh credential-stuffing risk.

Refusals are `ApiKeyRejection`: `401 invalid_token` and `403 insufficient_scope`
carry RFC 6750 `WWW-Authenticate`; `403 ip_not_allowed`, `403 request_not_allowed`,
and rate-limit responses do not. Format-miss and hash-miss share the same
body/headers. Presented tokens are `#[SensitiveParameter]` and never appear in
messages, `render()`, `__debugInfo`, JSON, or serialize output.

## Legacy matchers (product-owned)

The package ships the `LegacyTokenMatcher` contract and registration point only —
no product-specific matcher classes. Boot **fails** when `api-keys.legacy_matchers`
is non-empty without an **absolute** ISO-8601 timestamp with offset (`DATE_ATOM`)
or UTC `Z` (`API_KEYS_LEGACY_ACCEPT_UNTIL` / `api-keys.legacy.accept_until`), for
example `2027-01-01T00:00:00Z` or `2027-01-01T00:00:00+00:00`. Relative strings
(`now`, `tomorrow`, `+10 years`) and date-only values are rejected.

`TokenCodec::prefixOf($token, $now)` / `legacyMatcherFor($token, $now)` require `$now`.
A matcher is used only when `isAccepting($now) && now < min(config, acceptUntil())`
(exactly-at = rejected). Matcher output must be a **strict** prefix leaving at least
`max(20, matcher->secretLength())` characters (Externa `ek_` secret = **31**).
`prefixOf` must also recognise the bare stored `key_prefix` so rotation can migrate
the row. `legacyMatcherFor` returns null for canonical tokens.

Dispatch `Events\LegacyTokenUsed` only after **successful** authentication, using
`AuthenticationResult::$legacyMatcherClass`:

```php
// Product-owned matcher (example shape only — not shipped by this package):
// ek_ + 9 alnum public id + 31 alnum secret (real Externa format)
final class EkLegacyTokenMatcher implements LegacyTokenMatcher { /* ... */ }

// config/api-keys.php
'legacy_matchers' => [EkLegacyTokenMatcher::class],
'legacy' => [
    // Absolute ISO-8601 with offset (DATE_ATOM) or UTC Z — not "tomorrow" / "+10 years"
    'accept_until' => env('API_KEYS_LEGACY_ACCEPT_UNTIL'), // e.g. 2027-01-01T00:00:00Z
],

$result = $authenticator->authenticate($presented, $context);
if ($result->legacyMatcherClass !== null) {
    event(new LegacyTokenUsed(
        $result->record->keyPrefix(),
        $result->legacyMatcherClass,
        /* matcher acceptUntil from your registry */,
    ));
}
event(new ApiKeyAuthenticated(
    $result->record->id(),
    $result->record->keyPrefix(),
    $result->usedPreviousSecret,
    $context->ip,
));
```

Pest helpers (`assertTokenAbsentFrom`, `assertInvalidToken`, `assertInsufficientScope`,
`assertIpNotAllowed`, `assertLegacyTokenUsed`) ship under `Qiick\ApiKeys\Testing\` via
**autoload-dev** only. Consumer apps should `require` `vendor/qiick/laravel-api-keys/src/Testing/functions.php`
from their `Pest.php` (do not put them on production `autoload.files`).

## Development

```bash
composer update
composer test      # Pest
composer lint      # Pint
composer analyse   # PHPStan level max
```


No `composer.lock` is committed (library). CI resolves with `--prefer-lowest` and stable
across PHP 8.3/8.4/8.5 × Laravel 12/13.

## Security

Private vulnerability reporting: see [SECURITY.md](./SECURITY.md).

## License

MIT. See [LICENSE](./LICENSE).
