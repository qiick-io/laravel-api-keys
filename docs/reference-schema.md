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
| `ip_allowlist` | json | yes | null | — | A JSON list. SQL NULL or `[]` → allow all; JSON `null`, an object (`{}` included) or anything malformed → deny |
| `restrictions` | json | yes | null | — | Versioned object below; SQL NULL → unrestricted; JSON `null` or anything without `v` = 1 (`{}`, `[]` included) → deny |
| `rate_limit_per_minute` | unsignedInteger | yes | null | — | Null → package default |
| `rate_limit_per_day` | unsignedInteger | yes | null | — | Null → no day bucket (rolling 86_400 s, not calendar) |
| `rate_limit_per_month` | unsignedInteger | yes | null | — | Null → no month bucket (rolling 2_592_000 s, not calendar) |
| `metadata` | json | yes | null | — | Labels under `metadata.labels`; never secrets |
| `expires_at` | **dateTime** | yes | null | index | Future-dated; index serves the expiry command |
| `expiry_notified_at` | timestamp | yes | null | — | Final success stamp for expiry notices |
| `expiry_notice_claimed_at` | timestamp | yes | null | — | In-flight claim lease (app clock); reclaimable after `api-keys.expiry.claim_lease_seconds` (keep above send latency; NTP-sync workers) |
| `expiry_notice_claim_token` | string(64) | yes | null | — | Token of the in-flight claim (random, from the command). Mark and release match it and the selected `expires_at`, so a run whose lease expired cannot touch the next run's claim and a rotation is never stamped as notified |
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
- **`hash_algorithm`:** `sha256` (SHA-256 of the whole presented token), the only algorithm in 1.x; changing it needs a major release (`docs/decisions/2026-11-24-sha-256-only.md`).
- **`credential_kind`:** `api_key`, `oauth_grant`.
- **`revoked_reason`:** `user`, `admin`, `owner`, `exposure`, `policy`, `reuse`,
  `reconsent`, `system` (superset of mcp-oauth `RevocationReason`).

### Reading the JSON columns

Hand `scopes`, `ip_allowlist` and `restrictions` to the package as stored:
`ApiKeyRecord::rawScopes()` and its siblings return
`$this->getRawOriginal('<column>')`. Do not read them through Laravel's
`array` or `json` cast for the package: those casts turn JSON that does not
decode into null, and a null allowlist or null restrictions mean "no
restriction". The authenticator decodes the stored string itself. A value
that does not decode (an empty string included) denies the key
(`ip_not_allowed`, `request_not_allowed` or `insufficient_scope`) and is
reported to the exception handler. So does a JSON object in `scopes` or
`ip_allowlist`, which must be lists (`{}` would otherwise read as an empty,
open allowlist). So does a JSON literal `null`: it is a value someone wrote,
not an absent one. SQL `NULL` keeps its meaning: none for `ip_allowlist` and
`restrictions`, and no usable scopes (deny) for `scopes`; an empty allowlist
`[]` still allows every IP. The model can keep the cast for its own UI code,
but the cast turns both SQL `NULL` and the JSON literal into PHP `null`, so
the `raw*()` accessors must return `getRawOriginal()`.

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

- Null, or an absent section, means unrestricted. A malformed value, a missing
  or unknown `v` (an empty `{}` or `[]` included), or an unknown key denies
  (fail closed, like `ip_allowlist`).
- Shapes are checked at every depth: the document, `request` and each resource
  entry are objects; `methods`, `route_names`, `origins`, `referrers`,
  `resources` and `values` are lists; `v` is the integer `1`. Any other shape
  (`"request": []`, `"methods": {}` or `null`, `"v": "1"`) denies. Only the
  `request` and `resources` sections may be `null` or absent; an absent list
  field is empty (unrestricted).
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

## Personal data erasure

The product's erasure orchestrator resolves `Qiick\ApiKeys\Erasure\ApiKeysEraser`
from the container. Bind `ApiKeyErasureRepositoryContract` to the product's
persistence adapter. The existing authentication repository binding is unchanged.
The eraser uses the adapter's connection and joins an open transaction as a
savepoint. The reference schema has no organisation discriminator, so a scoped
call throws `OrganisationScopeUnsupportedException`. Products with that flow
must erase their organisation-specific credentials using their tenant mapping.
[Fleet erasure standard](https://github.com/qiick-io/app-ui/blob/v0.15.0/standards/rules/erasure.md)

The adapter and orchestrator have these responsibilities.

- Capture the user's principal and API key UUIDs in the encrypted erasure
  request before principal cleanup. Keep the original map of owned key UUIDs to
  internal IDs in that snapshot. Implement `keyIdsFromSnapshot($userPublicId)`
  on the adapter to read the map from the current request. The eraser uses
  those IDs for cache cleanup even after the rows have gone, and takes live
  IDs when the same UUID appears in both maps. Block new writes for the
  subject and drain in-flight usage and warning work before erasing credentials.
- Match ownership via the principal directory and the trusted public IDs.
  Include direct owners on installations without principals. In `delete`
  mode remove solely owned credentials. In `anonymise` mode keep inert rows:
  revoke them, discard current and previous token material, replace the key
  UUID, and unlink the owner (use an unrelated, non-authenticating principal if
  the foreign key is required). Scrub user attribution, usage IP and agent,
  claim data, names, notes, metadata, restrictions, and any other personal
  values. In both modes preserve other owners' keys while unlinking
  `created_by` and `revoked_by` references. Scrub the supplied identifiers from
  names, descriptions, metadata and revocation notes even on keys where the
  subject has no attribution link.
  The user row belongs to the product's later access step.
- Suppress model events and identifying diagnostics such as query bindings.
  Return accurate row counts, including attribution-only updates, with the same
  counts on a read-only preview. Handle product columns, notification copies,
  jobs, audit and retention through the product's erasure steps.
- Cover custom attempt limiter and warning gate bindings, product-defined
  buckets, stores or prefixes no longer configured, and legacy warning
  markers and leases from previous cutoff settings. The package clears its
  default per-key minute, day and month counters and timers on
  `api-keys.cache_store` (or the default store), and the current-cutoff
  legacy markers and leases on the default store. Shared pre-auth IP buckets
  expire after 60 seconds. They can include requests from several users at the
  same network address, so the eraser leaves them to expire and excludes them
  from subject retention counts.

After the outermost commit, the eraser clears the cache entries and dispatches
`SubjectErasedEvent` with aggregate counts. A rollback leaves the cache alone.
If the cache fails after the database commits, retry from the encrypted
snapshot. Mark the step done only after the commit and cleanup return. A dry
run reports prospective counts without erasing or dispatching.
