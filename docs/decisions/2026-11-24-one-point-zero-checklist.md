# 2026-11-24: 1.0 checklist decisions

Team Leader bot, 2026-11-24, under Luca's rule "standard and safe". Taken from the
comparison of this package with the qiick packages 1.0 checklist and the standards
review of the package.

| Item | Decision | Why |
| --- | --- | --- |
| F8 Scanner adapter for `CompromisedKeyRevoker` | **LATER** (additive after 1.0). The package keeps the seam and the `ApiKeyExposed` recipe in the README. | A secret-scanning partner callback is a product route with the scanner's signature verification and its own secrets; the seam and the event are the stable contract, and an adapter adds nothing to the schema or the API. |
| F12 Maximum lifetime on issue | **Before 1.0, option (a):** public `LifetimeAssertion::assertAllows()` plus a README recipe that the product calls before inserting a key; `RotationService` uses the same assertion. | Issuance is product-owned (`TokenCodec::issue()` writes nothing), so an `IssuanceService` would add contract for little gain. One assertion gives one refusal for both paths. It is a static helper, not a method on `LifetimePolicy`, so implementations of the interface do not change. |
| F13 UTC timestamps | **Before 1.0:** `php artisan api-keys:check` fails when `app.timezone` is not `UTC`. | Expiry, grace and claim-lease comparisons assume UTC (RFC 3339 on the wire); a deploy-time check catches a misconfigured app without breaking every artisan command. |
| L3 Day/month buckets | **Changed:** counted by the package's atomic `CacheAttemptLimiter` (Lua on Redis, `add` + `increment` on Memcached), not by Laravel's `RateLimiter` as the standards review said. | Proven in the review of #28: `RateLimiter::increment()` recreates counters with a non-atomic `put()` and the database store is not atomic, so 50 parallel attempts against a limit of 10 let up to 36 through, and late decrements left counters negative. |
| Checklist 3, mutation gate scope | **Every class in `src/` is in the per-class ≥95% gate, except:** the interfaces in `src/Contracts` (no executable code), enums without methods (`CredentialKind`, `ExpiryRecipient`, `KeyRejectionCode`, `RevocationReason`, `TokenEnvironment`, `TokenMatch`), and the `Qiick\ApiKeys\Testing` namespace (test doubles, not runtime code). | Nothing in them can be mutated into a behaviour change, or (Testing) they never run in a product. Everything else runs in production and must be proven by its tests. |
