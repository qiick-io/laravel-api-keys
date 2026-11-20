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
HTTP middleware. This package does not register middleware or Artisan commands.

Part of the qiick fleet. Binding design:
`projects/qiick/packages/laravel-api-keys-design.md` in the knowledge base
(overlay: `decisions/2026-11-20-core-hardening.md`).

## Status

Pre-`0.1.0`. Public APIs may change in any 0.x release; see [UPGRADING.md](./UPGRADING.md).
Do not require this package from production apps until a tagged release lands on Packagist
(Packagist publish only after Luca’s go).

## Requirements

- PHP `^8.3`
- Illuminate contracts / http / support `^12.0 \|\| ^13.0` (never `laravel/framework`)

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
| Failed-attempt brake | Buckets IPv4 by `/32` and IPv6 by `/64`. IPv4-mapped (`::ffff:a.b.c.d`) expands to dotted IPv4 before bucketing (same path as `IpAllowlist`). Null/empty/unparseable client IPs **skip** the brake (never share one bucket — that would lock out everyone behind a misconfigured proxy). Repository/infra exceptions are **not** counted. Shared egress / NAT: many clients behind one public IP share one bucket and can lock each other out; keep the recipe default **on** (20/min) and raise only with a clear threat model. Wire after `TrustProxies` so `KeyContext::ip` is the real client, not the LB. |
| Redaction | Presented tokens / Bearer values MUST NEVER appear in exception messages, JSON bodies, logs, telemetry, activity properties, or `__debugInfo`. |
| Scopes | Fail-closed: whitespace, wrong case, duplicates, or non-vocabulary values → empty set → `403 insufficient_scope` (never 401). |
| Audit | Activity under a key carries `api_key_id` = the key’s **public UUID** via `Audit::withApiKeyId` (never the internal bigint; lowercase UUID; rejects non-UUID, nil UUID, and a conflicting existing `api_key_id`). |
| Rotation | `RotationService::rotate(ApiKeyRecord, TokenCodec, Clock, graceHours)` refuses revoked/expired keys and unknown prefixes (legacy only while the matcher still accepts `$now`); invalid/negative/above-max grace → 0 (max default 168h, bound from `rotation_max_grace_hours`). Legacy prefixes migrate to a **fresh canonical** token with **no grace across formats** (old `ek_` plaintext dies as soon as `key_prefix` is updated). Matchers must recognise a bare stored prefix. Products **must** `lockForUpdate` and write `key_prefix` / `key_hash` / `previous_key_hash` / `previous_key_valid_until` unconditionally. |

## Token shape

`{product}_{live|test}_{id}{secret}` — three-letter product prefix, 8-character
public id, 32-character secret (A–Za–z0–9, ≥160 bits via `RandomSource`). The row
stores SHA-256 of the **full** plaintext. Issue via `TokenCodec` with injectable
`EnvironmentResolver` and `RandomSource` (tests: `FixedEnvironment`,
`FixedRandomSource`).

## Rotation (product persistence)

```php
DB::transaction(function () use ($key, $codec, $clock) {
    $locked = ApiKey::query()->whereKey($key->id)->lockForUpdate()->firstOrFail();
    $rotation = $rotationService->rotate($locked, $codec, $clock, config('api-keys.rotation_grace_hours'));

    // Write all four columns unconditionally (nulls when grace is 0;
    // key_prefix changes when migrating a legacy ek_ row onto canonical —
    // that cut-over is immediate: no grace across formats).
    $locked->forceFill([
        'key_prefix' => $rotation->newKeyPrefix,
        'key_hash' => $rotation->newKeyHash,
        'previous_key_hash' => $rotation->previousKeyHash,
        'previous_key_valid_until' => $rotation->previousKeyValidUntil,
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

`ApiKeyAuthenticator::authenticate($presentedToken, $context, $requiredScope)`:

1. Pre-auth `FailedAttemptLimiter` (IPv4 `/32`, IPv6 `/64`; default 20/min in recipes) →
2. Parse bearer (no trim; case-insensitive `Bearer`; `BearerTokenExtractor`) →
3. Token format → 4. Lookup + `hash_equals` (dummy on miss) → 5. Revoked/expired →
6. Actor (`KeyAuthorizer`) → 7. IP allowlist → 8. Scopes: expand → owner ceiling
   (fail-closed if no owner/creator; write may demote to read) → collapse highest-per-resource →
9. Per-key rate limit (`AttemptLimiter`, default bucket `api-key:{id}`) →
10. Usage record (`UsageRecorder` throttle; write failures are reported, not thrown).

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
carry RFC 6750 `WWW-Authenticate`; `403 ip_not_allowed` does not. Format-miss and
hash-miss share the same body/headers. Presented tokens are `#[SensitiveParameter]`
and never appear in messages, `render()`, `__debugInfo`, JSON, or serialize output.

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
