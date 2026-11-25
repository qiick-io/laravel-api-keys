# Public API

Everything listed here is the public API frozen at 1.0: it changes only as the
deprecation policy in the README allows. Everything else in `src/` is marked
`@internal` and may change in any release. `tests/Arch/PublicApiTest.php` fails
when a class is neither `@api` nor `@internal`, or when an `@api` class is
missing from this page.

## Classes, interfaces and enums

Public means the class name, its public methods and constructor, and for enums
the case names and backing values (backing values are wire or storage values).
Internal on purpose: `RequestRestrictionsEvaluator`, `AppEnvironmentResolver`,
`RandomBytesSource`, `PublicSuffixList` and `EnsuresTestingEnvironmentTrait`.
`UsageRecorder` and `TokenMatch` stay public because public signatures use them
(`ApiKeyAuthenticator::__construct()` and `TokenCodec::match()`).

### `Qiick\ApiKeys`

- `ApiKeyAuthenticator` (class)
- `Audit` (class)
- `AuthenticationResult` (class)
- `AuthorizationDecision` (class)
- `CacheAttemptLimiter` (class)
- `CacheLegacyFormatWarningGate` (class)
- `ConfigLifetimePolicy` (class)
- `CredentialKind` (enum)
- `DatabaseAttemptLimiter` (class)
- `ExpiryNoticeClaimSql` (class)
- `ExpiryRecipient` (enum)
- `FailedAttemptLimiter` (class)
- `GeneratedToken` (class)
- `IpAllowlist` (class)
- `KeyContext` (class)
- `KeyRejectionCode` (enum)
- `KeyRestrictions` (class)
- `LegacyTokenMatcher` (interface)
- `LifetimeAssertion` (class)
- `ParsedToken` (class)
- `RateLimitDecision` (class)
- `RequestRestrictions` (class)
- `ResourceRestriction` (class)
- `ResourceRestrictions` (class)
- `RevocationReason` (enum)
- `Rotation` (class)
- `RotationService` (class)
- `Scope` (class)
- `ScopeSet` (class)
- `SystemClock` (class)
- `TokenCodec` (class)
- `TokenEnvironment` (enum)
- `TokenMatch` (enum)
- `UsageRecorder` (class)

### `Qiick\ApiKeys\Console\Commands`

- `CheckApiKeysConfigurationCommand` (class)
- `NotifyExpiringApiKeysCommand` (class)
- `PruneApiKeyAttemptsCommand` (class)

### `Qiick\ApiKeys\Contracts`

- `ApiKeyRecord` (interface)
- `ApiKeyRepository` (interface)
- `AttemptLimiter` (interface)
- `Clock` (interface)
- `CompromisedKeyRevoker` (interface)
- `EnvironmentResolver` (interface)
- `ExpiryRecipientResolver` (interface)
- `KeyAuthorizer` (interface)
- `LegacyFormatWarningGate` (interface)
- `LifetimePolicy` (interface)
- `RandomSource` (interface)
- `ScopeVocabulary` (interface)
- `UsageSideEffect` (interface)

### `Qiick\ApiKeys\Events`

- `ApiKeyAuthenticated` (class)
- `ApiKeyExpiryNoticeSent` (class)
- `ApiKeyExposed` (class)
- `ApiKeyLegacyFormatWarningSent` (class)
- `LegacyTokenUsed` (class)

### `Qiick\ApiKeys\Exceptions`

- `ApiKeyRejection` (class)

### `Qiick\ApiKeys\Http`

- `BearerTokenExtractor` (class)
- `ClientIp` (class)
- `KeyContextFactory` (class)

### `Qiick\ApiKeys\Laravel`

- `ApiKeysServiceProvider` (class)

### `Qiick\ApiKeys\Notifications`

- `ApiKeyExpiringNotification` (class)
- `ApiKeyLegacyFormatWarningNotification` (class)

### `Qiick\ApiKeys\Testing`

- `ArrayScopeVocabulary` (class)
- `DummyMatchProbe` (class)
- `FakeApiKeyRepository` (class)
- `FakeAttemptLimiter` (class)
- `FakeExpiryRecipientResolver` (class)
- `FakeKeyAuthorizer` (class)
- `FakeLegacyFormatWarningGate` (class)
- `FixedClock` (class)
- `FixedEnvironment` (class)
- `FixedRandomSource` (class)
- `InMemoryApiKeyRecord` (class)
### Testing functions (`Qiick\ApiKeys\Testing`, autoload-dev)

- `assertTokenAbsentFrom()`
- `assertInvalidToken()`
- `assertInsufficientScope()`
- `assertIpNotAllowed()`
- `assertLegacyTokenUsed()`

## Config keys

Every key sits under `api-keys.` in `config/api-keys.php`; the published file
documents each one.

- `product_prefix`
- `environment`
- `token_version`
- `rotation_grace_hours`
- `rotation_max_grace_hours`
- `usage_throttle_seconds`
- `usage_bypass_throttle_on_ip_change`
- `default_rate_limit_per_minute`
- `failed_attempts_per_minute`
- `attempt_limiter`
- `attempt_limiter_table`
- `max_lifetime_days`
- `expiry.notice_days`
- `expiry.claim_lease_seconds`
- `expiry.recipients`
- `expiry.notification`
- `legacy_matchers`
- `legacy.accept_until`
- `legacy.warn_days_before`
- `legacy.warning_notification`

The package also reads `app.timezone` (`api-keys:check` requires UTC) and the
default cache store (`cache.default`) and database connection (`database.default`)
for the bound `AttemptLimiter`.

## Environment variables

- `API_KEYS_ATTEMPT_LIMITER`
- `API_KEYS_ATTEMPT_LIMITER_TABLE`
- `API_KEYS_DEFAULT_RATE_LIMIT_PER_MINUTE`
- `API_KEYS_ENVIRONMENT`
- `API_KEYS_EXPIRY_CLAIM_LEASE_SECONDS`
- `API_KEYS_EXPIRY_NOTICE_DAYS`
- `API_KEYS_FAILED_ATTEMPTS_PER_MINUTE`
- `API_KEYS_LEGACY_ACCEPT_UNTIL`
- `API_KEYS_LEGACY_WARN_DAYS_BEFORE`
- `API_KEYS_MAX_LIFETIME_DAYS`
- `API_KEYS_PRODUCT_PREFIX`
- `API_KEYS_ROTATION_GRACE_HOURS`
- `API_KEYS_ROTATION_MAX_GRACE_HOURS`
- `API_KEYS_TOKEN_VERSION`
- `API_KEYS_USAGE_BYPASS_ON_IP_CHANGE`
- `API_KEYS_USAGE_THROTTLE_SECONDS`
- `QIICK_API_KEYS_ALLOW_FAKES` (tests only: lets the `Testing` doubles run outside `testing`)

## Artisan commands

- `api-keys:notify-expiring`
- `api-keys:check`
- `api-keys:prune-attempts`

## Publish tags

- `api-keys-config`

## Migrations

None. Products own the `api_keys` table and, for the database attempt limiter,
the `api_key_attempts` table; the normative columns are in
`docs/reference-schema.md`, and `Qiick\ApiKeys\ExpiryNoticeClaimSql` gives the
claim statements for each engine.

## Translations

Products may define these keys; each refusal falls back to an English message:
`api_keys.invalid_token`, `api_keys.insufficient_scope`, `api_keys.ip_not_allowed`,
`api_keys.no_usable_scopes`, `api_keys.rate_limit_exceeded`,
`api_keys.request_not_allowed`.

## Wire and storage formats

- Token shape `{product}_{live|test}_{id}{secret}[checksum]` and the scanner
  regex in the README; `token_version` 0 (legacy), 1, 2.
- Refusal `error` codes: `KeyRejectionCode` backing values; RFC 6750
  `WWW-Authenticate` on `invalid_token` and `insufficient_scope`; `Retry-After`
  and `X-RateLimit-*` on `rate_limit_exceeded` (`X-RateLimit-Reset` in seconds
  until the reset, not an epoch timestamp).
- `api_key_attempts` columns (`bucket`, `hits`, `expires_at` in Unix seconds)
  and the limiter bucket names stored in `bucket`.
- Stored values: `CredentialKind`, `RevocationReason`, `TokenEnvironment` and
  `ExpiryRecipient` backing values; the `restrictions` JSON shape version 1
  (`KeyRestrictions::VERSION`).
- Activity property `api_key_id` (`Audit::withApiKeyId`).

## Events

- `ApiKeyAuthenticated`
- `ApiKeyExpiryNoticeSent`
- `ApiKeyExposed`
- `ApiKeyLegacyFormatWarningSent`
- `LegacyTokenUsed`
