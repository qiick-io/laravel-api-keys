# Changelog

All notable changes to **laravel-api-keys** (`qiick/laravel-api-keys`) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `docs/reference-schema.md` is the full 1.0 reference products adopt: unique
  `key_prefix`, version/hash columns, restrictions JSON, quotas, revocation
  attribution, OAuth grant marking, usage and exposure fields, and the scanner
  regex. Products still own migrations.

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
