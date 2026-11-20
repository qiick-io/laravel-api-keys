# Security Policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| Untagged `develop` / pre-`0.1.0` | Best effort while the package is in development. |
| Tagged `0.x` / `1.x` (once published) | Documented here when the first tag lands. |

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting
("Report a vulnerability" on the Security tab of `qiick-io/laravel-api-keys`).
We aim to acknowledge reports within 72 hours.

This package is an authentication boundary. Reports about token hashing and
comparison, scope fail-closed behaviour, IP allowlist bypass, token redaction
leaks, rate-limit or failed-attempt brake bypasses, or grace/revoke invariants
are treated as critical.

## Trusted release path

Tagged releases are cut from `main` with GitHub attestations / build provenance
where available. Packagist publish happens only after Luca’s explicit go. Never
trust an untagged `develop` commit as a production dependency.
