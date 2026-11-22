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
  `exposed_at` / `exposure_source`, `revoked_by` / `revoked_reason` /
  `revocation_note`.
- No `owner_kind` or `oauth_grant_uuid` column (principal kind; grant id is
  `uuid`).

### Contract breaks

- `ApiKeyRecord`: add `publicId()`, version/hash/credential/restrictions/quota
  and attribution methods (see interface).
- `ApiKeyRepository::recordUsage(..., ?string $userAgent, ...)`; add
  `findByPublicId`, `expiringUnnotified`, `markExpiryNotified`;
  `findCandidatesByPrefix` also matches `previous_key_prefix` in grace.
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
