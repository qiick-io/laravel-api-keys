# Reference schema (products own migrations)

This package ships **no migrations**. Products own Eloquent models and tables.
The columns below are the fleet contract for adoption (see knowledge decision
`2026-11-20-core-hardening`).

## `api_keys` (conceptual)

| Column | Type | Notes |
| --- | --- | --- |
| `id` | bigint | Internal only; never leave the database |
| `uuid` | UUID (string) | Public id for APIs, webhooks, audit `api_key_id` |
| `key_prefix` | string | Non-secret lookup prefix |
| `key_hash` | string | SHA-256 of full presented token |
| `previous_key_hash` | string, nullable | Grace secret after rotation |
| `previous_key_valid_until` | **dateTime**, nullable | Future-dated: never MySQL `TIMESTAMP` |
| `scopes` | JSON / text | Stored list; parsed fail-closed by `ScopeSet` |
| `ip_allowlist` | JSON / text, nullable | Null/empty → allow all; malformed → deny |
| `rate_limit_per_minute` | int, nullable | Null → package default |
| `expires_at` | **dateTime**, nullable | Future-dated |
| `revoked_at` | timestamp/datetime, nullable | Past-event stamp |
| `last_used_at` | timestamp/datetime, nullable | Written via `saveQuietly` |
| `last_used_ip` | string, nullable | |
| `owner_principal_id` | FK | On delete: restrict or null+revoke job; never silent cascade |
| `created_by` | FK, nullable | On delete: null |
| `created_at` / `updated_at` | Laravel defaults | |

## Audit property

Every activity written under a key **must** carry `api_key_id` set to the key's
**public UUID** via `Qiick\ApiKeys\Audit::withApiKeyId`. Never the internal bigint.
