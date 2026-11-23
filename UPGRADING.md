# Upgrading

This package is **pre-release** (`0.x`). Breaking changes are allowed between
minor versions while the major is `0`, and each break is recorded here before a
tagged release.

## From 0.1.0 toward 1.0.0

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

- `AttemptLimiter` (red-team fix, atomic limits): `hit()` must atomically
  increment and return the new count; add `decrement()`; `tooManyAttempts()`
  is gone. With Laravel's `RateLimiter`, return `$rateLimiter->hit(...)` and
  forward `decrement()` (see the adapter in the README). `FailedAttemptLimiter`
  now exposes `reserve()` / `release()` instead of `tooManyAttempts()` / `hit()`.
- `LegacyFormatWarningGate`: `claim(string $key, int $leaseSeconds)`,
  `release(string $key)` and `markSent(string $key)`. Only custom gates need
  changes; the default cache gate is updated.
- `api-keys.max_lifetime_days` is now enforced on rotation by default, and a
  value that is not a whole number >= 1 fails at boot. Unset it to keep the
  previous (unenforced) behaviour.

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
- Day/month quotas (`rate_limit_per_day` / `rate_limit_per_month`) are **rolling
  windows** via Laravel's `RateLimiter` (decay seconds 86_400 / 2_592_000), not
  calendar day/month buckets. Durable calendar quotas remain LATER.
- Origin/referrer restriction patterns are structured: exact origin,
  `scheme://*.example.com[:port]` on the host-label boundary, and referrer path
  prefix only after an exact origin. Raw trailing `*` (e.g.
  `https://app.example.com*`) is rejected at parse time.
- `Qiick\ApiKeys\Testing\*` doubles refuse construction unless
  `app()->environment('testing')` or `QIICK_API_KEYS_ALLOW_FAKES=1`.
