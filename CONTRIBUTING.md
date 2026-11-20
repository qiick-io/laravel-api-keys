# Contributing to laravel-api-keys

Thanks for helping. A few rules keep the codebase consistent:

1. Open or pick an issue first. One cohesive area per pull request.
2. Branch from `develop` as `<type>/<kebab-slug>` (types: feat, fix, refactor,
   chore, docs, test, perf, ci, build, security).
3. Use Conventional Commits; PR titles follow the same format. Body lines ≤ 100
   characters.
4. Open the PR against `develop`. PRs are squash-merged. Never push to
   `develop` or `main` directly; never tag from a contributor branch.
5. Before pushing run `composer test` (Pest), `composer lint` (Pint) and
   `composer analyse` (PHPStan level max). Security-critical classes also need
   `pest --mutate` coverage (see the design §6 mutation targets).
6. Red-first: add a failing test for the property, then the implementation.
   Tests are deterministic only (injectable clock, environment, CSPRNG; no
   network).
7. Code style: strict types, `final` by default, English docblocks that explain
   *why*, no global helpers. Only `@api` types are SemVer BC; Arch tests guard
   accidental public-surface growth.
8. Security checks are never weakened. Changes to hashing, scopes, allowlist,
   rejection redaction, grace/revoke, or rate brakes need a test that proves the
   bad value is refused.
9. Do not commit `composer.lock`, secrets, or `graphify-out/`.
10. Releases and Packagist: maintainer only (see SECURITY.md and the qiick
    release standard).
