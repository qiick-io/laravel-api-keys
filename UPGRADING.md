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

Contract and behaviour breaks (record methods, token v2 default, restrictions,
rate-limit list return, expiry command, and so on) land in follow-up 0.x PRs
and are listed here as each ships.
