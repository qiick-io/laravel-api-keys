# Upgrading

This package is **pre-release** (`0.x`). Breaking changes are allowed between
minor versions while the major is `0`, and each break is recorded here before a
tagged release.

## Every release: Public Suffix List refresh

Origin wildcards are checked against a bundled snapshot of the Public Suffix
List (`resources/public_suffix_list.php`); a monthly workflow opens an issue
when the upstream list changed, and a maintainer refreshes it by pull request.
Patterns are re-validated on every request, so a refresh that lists a new
suffix makes stored origin wildcards over it (for example a new hosting
platform's `https://*.platform.example`) parse as denied: those keys stop
authenticating after you upgrade, with no migration. Each CHANGELOG entry says
whether the list changed; before upgrading, search stored `restrictions` for
wildcards over the suffixes it names.

## From 0.3.0-beta.2 to 0.3.0-beta.3

- A JSON literal `null` (the stored text `null`) in `scopes`, `ip_allowlist`
  or `restrictions` now denies the key and is reported. So does `null` in a
  request list field (`methods`, `route_names`, `origins`, `referrers`).
  - SQL NULL keeps its meaning: in `ip_allowlist` or `restrictions` it means
    "none", and in `scopes` it still denies (no usable scopes). An empty
    allowlist `[]` still allows every IP.
  - When repairing rows, restore the intended scopes, and use SQL NULL only for
    an allowlist or restrictions document that is meant to be absent.
  - The distinction only reaches the package through the raw accessor
    (`ApiKeyRecord::rawIpAllowlist()` and its siblings returning
    `getRawOriginal()`): Laravel's `array` cast turns both into PHP `null`
    before the authenticator can check.
- `KeyRestrictions::parse()` denies `[]`, `''` and any document without
  `v` = 1; only null is unrestricted. Store null, not `{}` or `[]`, for a key
  without restrictions, or those keys stop authenticating (fail closed).
- A stored `scopes` or `ip_allowlist` that is a JSON object instead of a list
  denies the key and is reported.
- `restrictions` shapes are checked at every depth (docs/reference-schema.md).
  An array cannot tell `{}` from `[]`, so a decoded array with an empty section
  (`['v' => 1, 'request' => []]`) now denies. Pass the stored string
  (`getRawOriginal('restrictions')`) as the contract asks.
- An `ip_allowlist` entry whose prefix has a leading zero (`203.0.113.0/024`,
  `10.0.0.1/00`) is now invalid, and a list holding one denies the key. Write
  prefixes without leading zeros; `IpAllowlist::isValidEntry()` validates form
  input by the same rules.
- **Contract break, `ApiKeyRepository`:** the expiry-notice claim is bound to
  a token and to the selected expiry.
  - Add `expiry_notice_claim_token` (string(64), nullable) to `api_keys`.
    Pre-1.0 products put it in their `create_api_keys` migration.
  - `claimExpiryNotice($record, $now, $leaseSeconds, string $claimToken): bool`
    also sets the token, and wins only while `expires_at` is still the
    selected expiry, matched within `ExpiryNoticeClaimSql::expiryWindow()`:
    from the start of its second to one second later.
  - `markExpiryNotified($record, $notifiedAt, string $claimToken): bool` and
    `releaseExpiryNotice($record, string $claimToken): void` apply only while
    the row holds that token and `expires_at`. Both clear the token, and the
    mark returns false when the claim was lost.
  - `ExpiryNoticeClaimSql` has the statements and their new bindings.
    `expires_from` and `expires_until` come from
    `ExpiryNoticeClaimSql::expiryWindow($record->expiresAt())`. Bind them like
    the column's other timestamps (same layout; an explicit offset for
    `TIMESTAMPTZ`), or no claim ever matches. `api-keys:notify-expiring` warns
    when it claims none of the notices it tried.

## From 0.3.0-beta.1 to 0.3.0-beta.2

- Redis or Memcached is no longer required. Attempts are counted with
  Laravel's `RateLimiter` on `API_KEYS_CACHE_STORE`, or on the default cache
  store when that is unset. Any store works, but only some are atomic across
  workers; docs/security.md has the table.
- **File store:** `api-keys:check` warns. Parallel workers can exceed the
  limits, even on one server.
- **SQLite database store:** set `'transaction_mode' => 'IMMEDIATE'` (PHP 8.4+)
  and a `busy_timeout` on the connection. Otherwise parallel requests answer 503.
- **Null store:** `api-keys:check` fails, because it keeps no counters.
- For production, use Redis, Memcached, DynamoDB, or the database store on
  MySQL or PostgreSQL.
- A window may admit up to just under twice its limit under load (Laravel's
  `put()` reset at window start, at most once per window). Earlier releases
  admitted exactly the limit on Redis and Memcached.
- `ApiKeyRecord::rawScopes()`, `rawIpAllowlist()` and `rawRestrictions()` must
  return the columns as stored, for example
  `return $this->getRawOriginal('ip_allowlist');`, not through the `array`
  cast. The cast turns JSON that does not decode into null, which reads as "no
  restriction". The authenticator now decodes the string, and a corrupted value
  denies the key and is reported. Decoded arrays are still accepted, so nothing
  breaks if you have not switched yet, but the fail-open case stays until you do.
- `ApiKeyRejection::insufficientScope()` and `noUsableScopes()` throw
  `InvalidArgumentException` for a scope that is not a scope atom
  (`Scope::PATTERN`, such as `items:read`). Pass `Scope::value()`, never raw
  user input.
- `SystemClock` now follows Laravel's clock (`Date::now()`). Tests that freeze or
  travel time move the package's expiry, grace and lease checks too. A
  product `Clock` binding still wins.
- Optional: set `API_KEYS_RESOURCE_METADATA_URL` to your RFC 9728
  protected-resource metadata (absolute https) so the `invalid_token` and
  `insufficient_scope` challenges point MCP / OAuth clients to it.

## From 0.2.0 to 0.3.0-beta.1

### Contract breaks

- `AttemptLimiter` (red-team fix, atomic limits): `hit()` must atomically
  increment and return the new count; add `decrement(string $key)` (no-op on
  a missing counter, never below zero); `tooManyAttempts()` is gone. Delete any
  adapter over Laravel's `RateLimiter` (it is not atomic) and use the bound
  `CacheAttemptLimiter`, which needs a Redis or Memcached default cache store.
  `FailedAttemptLimiter` now exposes `isBlocked()` / `countFailure()` instead of `tooManyAttempts()` / `hit()`;
  `RateLimitDecision` refuses `decaySeconds` below 1.
- `LegacyFormatWarningGate`: `claim(string $key, int $leaseSeconds): ?string`
  returns an owner token; `release(string $key, string $ownerToken)` and
  `markSent(string $key, string $ownerToken)`. Only custom gates need
  changes; the default cache gate is updated.
- `new RequestRestrictions(...)` validates its lists and patterns and throws
  `InvalidArgumentException`. Stored `restrictions` rows holding a pattern that
  is now invalid (for example `https://*.com`, `https://*.github.io` or
  `https://*.co.uk`) parse as denied, so those keys stop authenticating after
  the upgrade (fail closed): narrow the pattern to your own domain first.
  `ApiKeyAuthenticator` no longer takes a `requestRestrictionsEvaluator`
  argument.
- The bound attempt limiter needs Redis or Memcached (array in tests): on any
  other default cache store, the first authentication throws. Set
  `CACHE_STORE=redis` (or bind your own `AttemptLimiter`) and add
  `php artisan api-keys:check` to the deploy pipeline, which fails on an
  unsupported store. Boot itself fails when
  `API_KEYS_FAILED_ATTEMPTS_PER_MINUTE`, `API_KEYS_EXPIRY_CLAIM_LEASE_SECONDS`
  or `API_KEYS_LEGACY_WARN_DAYS_BEFORE` is not digits only.
- `api-keys.max_lifetime_days` is now enforced on rotation by default, and a
  value that is not a whole number >= 1 fails at boot. Unset it to keep the
  previous (unenforced) behaviour.

## From 0.1.0 to 0.2.0

### Reference schema

`docs/reference-schema.md` is the normative column list products adopt. Notable
pre-1.0 additions versus the 0.1.0 sketch:

- `key_prefix` is **unique** (`string(32)`); `key_hash` stays unique.
- New columns: `token_version`, `hash_algorithm`, `previous_key_prefix`,
  `credential_kind`, `oauth_client_id`, `description`, `metadata`,
  `restrictions`, `rate_limit_per_day` / `rate_limit_per_month`,
  `last_used_user_agent`, `last_rotated_at`, `expiry_notified_at`,
  `expiry_notice_claimed_at`, `exposed_at` / `exposure_source`,
  `revoked_by` / `revoked_reason` / `revocation_note`.
- No `owner_kind` or `oauth_grant_uuid` column (principal kind; grant id is
  `uuid`).

### Contract breaks

- `ApiKeyRecord`: add `publicId()`, version/hash/credential/restrictions/quota
  and attribution methods (see interface).
- `ApiKeyRepository::recordUsage(..., ?string $userAgent, ...)`; add
  `findByPublicId`, `expiringUnnotified`, `markExpiryNotified`,
  `claimExpiryNotice($record, $now, $leaseSeconds)` /
  `releaseExpiryNotice` (lease CAS before send; mark after success);
  `ApiKeyRecord::expiryNoticeClaimedAt()`; `findCandidatesByPrefix` also
  matches `previous_key_prefix` in grace. Products implement claim via
  {@see \Qiick\ApiKeys\ExpiryNoticeClaimSql} (set
  `expiry_notice_claimed_at` when unsent and unclaimed or lease-expired;
  stamp `expiry_notified_at` only after a successful send). The lease uses
  **app/worker time** (bound `$now` / cutoff), not DB `NOW()`: clock skew
  across workers can reclaim a live claim early. Keep
  `api-keys.expiry.claim_lease_seconds` (default 900) above worst-case
  notification send latency, or an in-flight send can be reclaimed and
  produce a double notice.
- `KeyAuthorizer::scopesCreatorMayGrant(ApiKeyRecord, ...)` (was creator id);
  `rateLimit()` returns `list<RateLimitDecision>`; add `authorizeResources`.
- `UsageSideEffect::afterRecorded` gains `$userAgent`.
- `ApiKeyAuthenticated::$apiKeyId` is `string` (UUID only).
- `TokenCodec::issue()` defaults to token version 2; `match()` takes
  `$hashAlgorithm`.
- `Rotation` gains `previousKeyPrefix`, `lastRotatedAt`, `tokenVersion`.
  Legacy → canonical rotations with grace keep `previous_key_prefix`.
- New denial: `ApiKeyRejection::requestNotAllowed()` → `403 request_not_allowed`.
- Runtime deps: `illuminate/console`, `illuminate/notifications`.
- New Artisan command: `api-keys:notify-expiring` (bind `ExpiryRecipientResolver`).
- Day/month quotas (`rate_limit_per_day` / `rate_limit_per_month`) are windows of
  86_400 / 2_592_000 seconds, not calendar day/month buckets. Durable calendar
  quotas remain LATER. (Since 0.3.0-beta.1 they are counted by
  `CacheAttemptLimiter`, see above.)
- Origin/referrer restriction patterns are structured: exact origin,
  `scheme://*.example.com[:port]` on the host-label boundary, and referrer path
  prefix only after an exact origin. Raw trailing `*` (e.g.
  `https://app.example.com*`) is rejected at parse time.
- `Qiick\ApiKeys\Testing\*` doubles refuse construction unless
  `app()->environment('testing')` or `QIICK_API_KEYS_ALLOW_FAKES=1`.
