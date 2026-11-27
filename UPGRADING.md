# Upgrading

This package is **pre-release** (`0.x`). Breaking changes are allowed between
minor versions while the major is `0`, and each break is recorded here before a
tagged release.

## Product adoption for 1.0

Use a tagged Packagist version and commit the product lockfile. Remove any
development alias for the package. On products with an unfrozen schema, fold
API key changes into the existing migration that creates `api_keys`, then verify
install from an empty isolated database. For existing data, plan a backfill
and rollback before changing ownership, uniqueness or column types.

### Every product

- Match the [reference schema](docs/reference-schema.md#api_keys) and keep its
  UUID separate from the internal key used for cache buckets. Preserve existing
  token versions and hashes. Write the version from new issuance (2 by default),
  and store the SHA-256 of the complete token. Persist every rotation field under
  a row lock, including the previous prefix, hash and expiry. Treat grant rows
  as `oauth_grant`, with their client UUID, and refuse them on the API-key path.
- Implement `ApiKeyRecord` and `ApiKeyRepository` around the product's model.
  Match current and unexpired previous prefixes and return raw stored JSON
  from the three `raw*()` accessors. Keep nullable SQL columns distinct from
  JSON literal nulls. Repair explicit null resource modes by restoring the
  intended rule before deploying the stricter decoder.
- Apply product permissions and resource restrictions in `KeyAuthorizer`,
  including the current owner's permissions. Call `LifetimeAssertion` before
  persisting issuance. Keep write policies, token redaction and the show-once
  secret flow at the product boundary. Pass the configured failed-attempt brake
  and the trusted client IP to the authenticator. Run `api-keys:check` on deploy.
- Missing Bearer credentials now return `401` with `WWW-Authenticate: Bearer
  realm="api-keys"` and optional `resource_metadata`; the challenge has no
  `error` parameter. JSON still reports `invalid_token`. Keep invalid, revoked
  and expired credential challenges on the `invalid_token` path, and update
  middleware and response tests that used the same challenge for both cases.
- Update public event imports, registrations and queue handling using the
  event mapping below.
- When enabling expiry notices, bind the recipient resolver and schedule the
  command. Use a single conditional claim update for the selected expiry, lease,
  unsent notice and non-revoked key. Bind all timestamps as stored in UTC.
- Bind `ApiKeyErasureRepositoryContract` on the product's writer connection.
  Capture owned key UUIDs, their internal cache IDs and the principal ID in
  the encrypted resumable request before principal cleanup. Call `ApiKeysEraser`
  from the fleet erasure orchestrator. Prove delete, anonymise, attribution-only
  cleanup and retry, including cache cleanup after commit and product conformance
  C17. The [erasure contract](docs/reference-schema.md#personal-data-erasure)
  lists the row fields and compatibility stores the adapter must cover.

### Adopter-specific changes

- **Excubia.** Replace the development alias. The create migration has the
  restrict/NOT NULL principal owner, version, grace and lease columns. Give
  the prefix and hash columns binary collation on MySQL and MariaDB, and make
  `created_at` and `updated_at` non-null. Add `whereNull('revoked_at')` to
  `ApiKeyRepositoryService::claimExpiryNotice()` in the atomic claim update.
- **Signaculum.** Update the beta pin. Keep its required expiry and existing
  principal owner, grant, version, grace and lease columns. Give the prefix
  and hash columns binary collation on MySQL and MariaDB. Its repository
  already calls `ExpiryNoticeClaimSql::claim()`, which now checks revocation.
- **Instituta.** Add the missing reference columns to the `api_keys` block in
  `2026_11_12_220000_create_instituta_tenancy_and_index_tables.php`. Keep the
  declared UUID primary-key divergence and map it to `publicId()`. Add the
  unique hash constraint after checking for existing duplicates. Preserve
  tenancy columns and enforce the current principal's perimeter and the
  key's area and path limits in the authorizer.
- **Externa.** Adopt after stable using forward migrations. Add the reference
  fields for versions (`token_version`, `hash_algorithm`), previous prefix,
  credential kind and principal owner. Add description, request restrictions,
  day and month quotas, metadata, the three expiry notice fields, last-used
  user agent, rotation timestamp, exposure fields and revocation attribution
  and notes. Preserve the existing `oauth_client_id` and backfill those rows as
  `oauth_grant`. Check for duplicate current prefixes before making `key_prefix`
  unique, and keep comparisons case-sensitive. Backfill nullable `scopes`
  from the product's existing authorization data before enforcing required
  scopes. Expand `expires_at` and `previous_key_valid_until` to UTC `dateTime`
  storage with a rollback-compatible switch. Preserve `ek_` readers by
  marking those keys token version 0, keeping SHA-256 hashes, binding a legacy
  matcher with an absolute cutoff and persisting the previous prefix during
  rotation grace. Keep the nullable owner and existing role authorization in
  the adapter until their separate transition.

For Excubia and the second adopter, run product CI on the tagged version and
record at least one week of real use, or one product release cycle, before
the stable package release.

## Event names after 0.3.0-beta.3

Update the imports in `Event::listen()` registrations, listener type hints,
manual dispatchers, and event fakes and assertions. These classes stay in
`Qiick\ApiKeys\Events` and carry the same payloads.

| Previous class | Current class |
| --- | --- |
| `ApiKeyAuthenticated` | `ApiKeyAuthenticatedEvent` |
| `ApiKeyExpiryNoticeSent` | `ApiKeyExpiryNoticeSentEvent` |
| `ApiKeyExposed` | `ApiKeyExposedEvent` |
| `ApiKeyLegacyFormatWarningSent` | `ApiKeyLegacyFormatWarningSentEvent` |
| `LegacyTokenUsed` | `LegacyTokenUsedEvent` |

Drain jobs containing the old event objects before deploying the new classes.
Rebuild Laravel's event cache if the application caches discovered listeners.

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

## Expiry claims after 0.3.0-beta.3

- Products with a custom `ApiKeyRepository::claimExpiryNotice()` query must
  add `revoked_at IS NULL` to the same atomic update as the other claim guards.
  Using `ExpiryNoticeClaimSql::claim()` picks up the condition automatically.
  Revocation before the claim prevents the send. Once a claim succeeds, the
  send can already be in flight when revocation commits.

## From 0.3.0-beta.2 to 0.3.0-beta.3

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
  `v` = 1; only SQL NULL (PHP `null`) is unrestricted. Store SQL NULL, not
  `{}` or `[]`, for a key without restrictions, or those keys stop
  authenticating (fail closed).
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
