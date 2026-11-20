# qiick/laravel-api-keys

> **In development. Not released and not on Packagist yet: do not depend on it.**

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
| Failed-attempt brake | Buckets IPv4 by `/32` and IPv6 by `/64`. Null/empty/unparseable client IPs **skip** the brake (never share one bucket — that would lock out everyone behind a misconfigured proxy). Repository/infra exceptions are **not** counted. Shared egress / NAT: many clients behind one public IP share one bucket and can lock each other out; keep the recipe default **on** (20/min) and raise only with a clear threat model. Wire after `TrustProxies` so `KeyContext::ip` is the real client, not the LB. |
| Redaction | Presented tokens / Bearer values MUST NEVER appear in exception messages, JSON bodies, logs, telemetry, activity properties, or `__debugInfo`. |
| Scopes | Fail-closed: whitespace, wrong case, duplicates, or non-vocabulary values → empty set → `403 insufficient_scope` (never 401). |
| Audit | Activity under a key carries `api_key_id` = the key’s **public UUID** via `Audit::withApiKeyId` (never the internal bigint). |

## Token shape

`{product}_{live|test}_{id}{secret}` — three-letter product prefix, 8-character
public id, 32-character secret (A–Za–z0–9, ≥160 bits via `RandomSource`). The row
stores SHA-256 of the **full** plaintext. Issue via `TokenCodec` with injectable
`EnvironmentResolver` and `RandomSource` (tests: `FixedEnvironment`,
`FixedRandomSource`).

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
