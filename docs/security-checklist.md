# API key security checklist

The package's design assigns the A-items below. `SecurityChecklistTest` verifies
that each item has a named test. The paths are relative to `tests/`.

| Item | Property | Evidence |
| --- | --- | --- |
| A1 | Canonical ID and secret lengths | `Unit/TokenCodecTest.php` |
| A2, A2b | Constant-time digest comparison and indistinguishable lookup misses | `Unit/TokenCodecTest.php`, `Unit/ApiKeyAuthenticatorTest.php` |
| A3, A3b, A4 | Rotation grace and refusal of expired or revoked keys | `Unit/RotationServiceTest.php`, `Unit/ApiKeyAuthenticatorTest.php` |
| A5, A5b, A6 | Scope syntax, implications and the owner's authorization ceiling | `Unit/ScopeTest.php`, `Unit/ApiKeyAuthenticatorTest.php` |
| A7, A9, A9b | IP evaluated before scopes, CIDR and IPv4-mapped addresses | `Unit/ApiKeyAuthenticatorTest.php`, `Unit/IpAllowlistTest.php` |
| A8, A10, A11 | Correct status and RFC 6750 challenge on refusals | `Unit/ApiKeyAuthenticatorTest.php`, `Unit/ApiKeyRejectionTest.php` |
| A12 | Throttled usage writes and immediate recording after an IP change | `Unit/ApiKeyAuthenticatorTest.php` |
| A13, A13b | Legacy matching only with a registered matcher and a valid cutoff | `Unit/LegacyTokenMatcherTest.php`, `Unit/TokenCodecTest.php` |
| A14 | No presented token in refusals, diagnostics or exception traces | `Unit/ApiKeyRejectionTest.php`, `Unit/ApiKeyAuthenticatorTest.php` |
| A15, A17 | Pre-auth brake and per-key quotas, including concurrent hits | `Unit/ApiKeyAuthenticatorTest.php`, `Unit/ConcurrentAttemptLimitTest.php`, `Database/CacheAttemptLimiterConcurrencyTest.php` |
| A16 | Activity identifies a key by its public UUID | `Unit/AuditTest.php` |
| A18 | Deterministic token generation under test doubles | `Unit/TokenCodecTest.php` |

| Additional contract | Evidence |
| --- | --- |
| Stored scopes, allowlists and restrictions deny malformed values | `Unit/ApiKeyAuthenticatorTest.php`, `Unit/KeyRestrictionsTest.php` |
| Expiry claims match the selected expiry and prevent stale claims across four SQL engines | `Database/ExpiryNoticeClaimCasTest.php`, `Feature/ExpiryNoticeIdempotencyTest.php` |
| Erasure covers both modes, dry-run and retries, and clears the applicable cache entries after commit | `Erasure/ErasureConformanceTest.php` |
| Composer and runtime configuration validation | `Feature/ServiceProviderTest.php` and the CI Composer audit |

See [attempt limits](security.md) for the measured window-start race and
cache-store guarantees. The package has framework request/response and
notification integration tests. The product that owns the HTTP transport and
the notification routes tests those through its own server and runtime.
