# Reference schema (products own migrations)

This package ships **no migrations**. Products own Eloquent models and tables.
The columns below are the fleet contract for adoption (see the approved
`laravel-api-keys-standards-review` knowledge note, 2026-11-22).

Excubia, signaculum and instituta (pre-1.0) write this into their
`create_api_keys` migrations. Externa adds it additively after the package is
stable `1.0.0`. Instituta may keep `uuid` as the primary key as a declared
divergence: there `id` is the public id.

## `api_keys`

| Column | Type | Null | Default | Index | Notes |
| --- | --- | --- | --- | --- | --- |
| `id` | bigint unsigned, auto | no | — | PK | Internal only; never leave the database |
| `uuid` | uuid (v7) | no | generated | unique | Public id; `api_key_id` in audit |
| `name` | string(255) | no | — | — | Display name |
| `description` | text | yes | null | — | Optional longer copy |
| `key_prefix` | string(32) | no | — | **unique** | Non-secret lookup prefix; names exactly one row |
| `key_hash` | string(64) | no | — | unique | Digest of the full presented token |
| `token_version` | unsignedSmallInteger | no | `1` | — | `0` product legacy, `1` canonical, `2` checksum (default for new issuance) |
| `hash_algorithm` | string(16) | no | `'sha256'` | — | Verifier after lookup; unknown → fail closed |
| `previous_key_prefix` | string(32) | yes | null | index | Old prefix during grace (incl. legacy → canonical) |
| `previous_key_hash` | string(64) | yes | null | — | Grace secret after rotation |
| `previous_key_valid_until` | **dateTime** | yes | null | — | Future-dated: never MySQL `TIMESTAMP` |
| `credential_kind` | string(16) | no | `'api_key'` | index (`credential_kind`, `revoked_at`) | `api_key` or `oauth_grant` |
| `oauth_client_id` | uuid | yes | null | index | Set iff `credential_kind = oauth_grant` |
| `owner_principal_id` | FK principals (uuid) | no\* | — | index | Restrict, or null plus a revoke job; never silent cascade |
| `created_by` | FK users | yes | null | index | `nullOnDelete` |
| `scopes` | json | no | — | — | Parsed fail-closed by `ScopeSet` |
| `ip_allowlist` | json | yes | null | — | Null/empty → allow all; malformed → deny |
| `restrictions` | json | yes | null | — | Versioned shape below; null → unrestricted |
| `rate_limit_per_minute` | unsignedInteger | yes | null | — | Null → package default |
| `rate_limit_per_day` | unsignedInteger | yes | null | — | Null → no day bucket (rolling 86_400 s, not calendar) |
| `rate_limit_per_month` | unsignedInteger | yes | null | — | Null → no month bucket (rolling 2_592_000 s, not calendar) |
| `metadata` | json | yes | null | — | Labels under `metadata.labels`; never secrets |
| `expires_at` | **dateTime** | yes | null | index | Future-dated; index serves the expiry command |
| `expiry_notified_at` | timestamp | yes | null | — | Idempotency stamp for expiry notices |
| `last_used_at` | timestamp | yes | null | — | Written via `saveQuietly` |
| `last_used_ip` | string(45) | yes | null | — | |
| `last_used_user_agent` | string(512) | yes | null | — | Package truncates to 512 |
| `last_rotated_at` | timestamp | yes | null | — | Rotation-age policy |
| `exposed_at` | timestamp | yes | null | index | Secret-scanning / manual exposure |
| `exposure_source` | string(64) | yes | null | — | e.g. `github_secret_scanning`, `manual` |
| `revoked_at` | timestamp | yes | null | index | Past-event stamp |
| `revoked_by` | FK users | yes | null | — | `nullOnDelete` |
| `revoked_reason` | string(32) | yes | null | — | Package enum values (below) |
| `revocation_note` | text | yes | null | — | Free text; never secret material |
| `created_at`, `updated_at` | timestamp | no | Laravel | — | |

\* NOT NULL where the product has principals. Products without principals yet may
keep the owner column nullable until the principals programme lands.

### Value sets (package-backed; products do not invent values)

- **`token_version`:** `0` product legacy (e.g. externa `ek_`), accepted through
  a `LegacyTokenMatcher` until `accept_until`. `1` is
  `{product}_{env}_{id}{secret}`. `2` appends a 6-character base62 CRC32
  checksum (GitHub construction) and is the default for new issuance; `1` stays
  accepted.
- **`hash_algorithm`:** `sha256` (SHA-256 of the whole presented token).
- **`credential_kind`:** `api_key`, `oauth_grant`.
- **`revoked_reason`:** `user`, `admin`, `owner`, `exposure`, `policy`, `reuse`,
  `reconsent`, `system` (superset of mcp-oauth `RevocationReason`).

### Not in this schema

`collection_slugs`, `role_id`, `read_only`, tenancy columns, `owner_kind`,
`oauth_grant_uuid`, `max_lifetime_days`, and a separate `labels` column. Product
content stays on the product; labels live under `metadata.labels`. The grant id
**is** `api_keys.uuid`. Owner kind is read from the principal.

## `restrictions` JSON (version 1)

```json
{
  "v": 1,
  "request": {
    "methods": ["GET", "POST"],
    "route_names": ["api.v1.posts.*"],
    "origins": ["https://app.example.com"],
    "referrers": ["https://app.example.com/*"]
  },
  "resources": [
    { "type": "collection", "values": ["news"], "mode": "allow" }
  ]
}
```

- Null, or an absent section, means unrestricted. A malformed value, an unknown
  `v`, or an unknown key denies (fail closed, like `ip_allowlist`).
- `request` is generic HTTP; the package evaluates it (methods, route names,
  origins, referrers). A denial is `403 request_not_allowed`.
- Origin patterns: exact origin, or `https://*.example.com` (optional port) on
  the host-label boundary with scheme/port exact. Referrer patterns: exact
  string, or path prefix after an exact origin (`https://app.example.com/*`).
  Raw trailing `*` on an origin (`https://app.example.com*`) is rejected at
  parse time so `app.example.com.evil.com` cannot sneak through.
- `resources[].type` is an opaque product string. The package validates the
  shape and hands a `ResourceRestrictions` value object to the product.
- `mode` accepts only `allow` in version 1.
- A product keeps **one** authoritative copy of each restriction: either this
  column or its own column, never both written.

## Scanner regex (secret-scanning partners)

Canonical issued tokens (version 1 and 2), for a three-letter product prefix
`ppp`:

```text
\bppp_(?:live|test)_[A-Za-z0-9]{40}(?:[A-Za-z0-9]{6})?\b
```

Version 1 is 40 characters after the prefix (`id` 8 + `secret` 32). Version 2
adds 6 checksum characters. Products substitute their own prefix. Legacy product
formats stay in the product's own patterns.

## Audit property

Every activity written under a key **must** carry `api_key_id` set to the key's
**public UUID** via `Qiick\ApiKeys\Audit::withApiKeyId`. Never the internal bigint.

## Timestamps

Store in UTC. Products assert `app.timezone = UTC` in a conformance check. Wire
format is RFC 3339. Future-dated columns (`expires_at`,
`previous_key_valid_until`) use `dateTime`, not MySQL `TIMESTAMP`.
