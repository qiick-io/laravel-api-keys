# Changelog

All notable changes to **laravel-api-keys** (`qiick/laravel-api-keys`) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
