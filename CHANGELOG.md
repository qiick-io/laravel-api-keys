# Changelog

All notable changes to **laravel-api-keys** (`qiick/laravel-api-keys`) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Token version 2 (CRC32 checksum, GitHub construction) as the default issuance;
  version 1 stays accepted. `token_version` / `hash_algorithm` on the record;
  unknown values fail closed.
- `previous_key_prefix` grace lookup (including legacy → canonical rotations).
- Versioned `restrictions` JSON (`request` + `resources`),
  `403 request_not_allowed`, and `KeyContextFactory`.
- Day/month rate-limit columns; `KeyAuthorizer::rateLimit()` returns a list;
  optional `X-RateLimit-Reset`.
- OAuth grant marking (`credential_kind`) with authenticator and rotation refusal.
- Revocation attribution, metadata/labels, `last_used_user_agent`, exposure fields.
- `api-keys:notify-expiring` command, `expiry_notified_at`, recipient resolver seam,
  `LifetimePolicy` / `CompromisedKeyRevoker` contracts.
- Expanded testing fakes and red-first tests named after standards review items.
- N2: legacy-format T−90 warning via `api-keys:notify-expiring`, `LegacyFormatWarningGate`, and `ApiKeyLegacyFormatWarningNotification`.

### Changed

- `docs/reference-schema.md` is the full 1.0 reference products adopt: unique
  `key_prefix`, version/hash columns, restrictions JSON, quotas, revocation
  attribution, OAuth grant marking, usage and exposure fields, and the scanner
  regex. Products still own migrations. (Landed in #15.)
- `ApiKeyRecord` / `ApiKeyRepository` / `KeyAuthorizer` / `UsageSideEffect` contracts
  for the 1.0 surface (`publicId()`, C1 ceiling takes the record, usage takes
  user agent). `ApiKeyAuthenticated::$apiKeyId` is a UUID string.
- `ApiKeyRepository::claimExpiryNotice` / `releaseExpiryNotice` plus
  `expiry_notice_claimed_at` lease (reclaim after
  `api-keys.expiry.claim_lease_seconds`); `markExpiryNotified` after send.
  Portable SQL in `ExpiryNoticeClaimSql`; Fake uses versioned CAS.
- Origin/referrer evaluation lowercases scheme and host before compare.

### Fixed

- Concurrent `api-keys:notify-expiring` runs can no longer double-send after a
  lost race on the claim lease; a worker that dies after claim no longer
  suppresses the notice forever.
- Mixed-case Origin / Referer hosts no longer false-deny against lowercase patterns.

## [0.1.0] - 2026-11-20

First pre-release. The API may still change before 1.0.0; see UPGRADING.md.

### Added

- `RotationService` (bound with `api-keys.rotation_max_grace_hours`, default cap 168 h): rotates
  from the stored `ApiKeyRecord`, refuses revoked or expired keys and unknown prefixes, keeps one
  previous secret for the grace window (0 = immediate), and turns a legacy key into a canonical one
  (the old legacy token stops working at once). Products lock the row and write every field.
- `Audit::withApiKeyId()`: the `api_key_id` audit property, always the key's public UUID (lowercased,
  nil UUID refused, a conflicting existing value throws).
- Legacy tokens: the `LegacyTokenMatcher` contract (declared secret length, bare stored prefix for
  rotation) with an end-of-life enforced by the package as `min(api-keys.legacy.accept_until,
  matcher)`; `accept_until` must be an absolute ISO-8601 timestamp (offset or UTC `Z`) and is
  validated at boot; `isAccepting()` can stop legacy tokens earlier.
- Events `ApiKeyAuthenticated` and `LegacyTokenUsed` (fired only after successful authentication,
  never carrying secret material); Pest helpers loaded only in development.
- `ApiKeyAuthenticator` with the fixed evaluation order (failed-attempt guard →
  format → lookup + `hash_equals` / dummy miss → revoked/expired → actor → IP →
  scopes narrowed by owner ceiling → rate limit → usage), `ApiKeyRejection`
  (RFC 6750 fleet `{message,error[,scope]}`, translator hook, token redaction),
  `FailedAttemptLimiter`, `BearerTokenExtractor` (no trim, case-insensitive
  scheme), `UsageRecorder` (usage write failures reported, not thrown),
  `#[SensitiveParameter]` on token/secret parameters, contracts and test fakes.
- `IpAllowlist` (IpUtils + IPv4-mapped unwrap, mapped CIDR prefix−96, zone-id
  denied, prefix-range fail-closed) and `Http\ClientIp` (`Request::ip()` only).
- `Scope` / `ScopeSet` with fail-closed `parseStored`, write⊇read, highest-per-resource, and `ArrayScopeVocabulary` test double.
- `TokenCodec` with injectable `Clock` / `EnvironmentResolver` / `RandomSource`
  seams, `GeneratedToken` / `ParsedToken`, live|test issue/parse/hash/match
  (full-token SHA-256 + `hash_equals`, dummy compare on miss), and Fixed*
  test doubles. Service provider binds the production seams and fails when
  legacy matchers are registered without `api-keys.legacy.accept_until`.
- Package scaffold: auto-discovered `ApiKeysServiceProvider`, publishable
  `config/api-keys.php` (tag `api-keys-config`), Pest + Testbench, Pint, PHPStan
  level max, qiick standards pack pinned to app-ui `v0.11.0`, CI matrix
  (PHP 8.3/8.4/8.5 × Laravel 12/13 × lowest/stable) with `composer validate
  --strict`, `composer audit`, and SHA-pinned Actions.

[Unreleased]: https://github.com/qiick-io/laravel-api-keys/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/qiick-io/laravel-api-keys/releases/tag/v0.1.0
