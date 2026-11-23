#!/usr/bin/env bash
# Enforce pest --mutate --min=95 on each security-critical class separately.
# A combined --class CSV can hide a weak class behind a high overall score.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CLASSES=(
  'Qiick\ApiKeys\TokenCodec'
  'Qiick\ApiKeys\Scope'
  'Qiick\ApiKeys\ScopeSet'
  'Qiick\ApiKeys\IpAllowlist'
  'Qiick\ApiKeys\ApiKeyAuthenticator'
  'Qiick\ApiKeys\Exceptions\ApiKeyRejection'
  'Qiick\ApiKeys\UsageRecorder'
  'Qiick\ApiKeys\FailedAttemptLimiter'
  'Qiick\ApiKeys\RotationService'
  'Qiick\ApiKeys\Audit'
  'Qiick\ApiKeys\Http\BearerTokenExtractor'
  'Qiick\ApiKeys\KeyRestrictions'
  'Qiick\ApiKeys\RequestRestrictionsEvaluator'
  'Qiick\ApiKeys\RequestRestrictions'
)

# CacheAttemptLimiter's Redis and Memcached branches only run against live
# servers: the CI "mutate (cache limiter)" job starts both and sets
# API_KEYS_LIMITER_STORE=both; elsewhere the class is skipped, not scored low.
if [[ "${API_KEYS_LIMITER_STORE:-}" == "both" ]]; then
  CLASSES+=('Qiick\ApiKeys\CacheAttemptLimiter')
fi

if [[ -n "${MUTATE_ONLY:-}" ]]; then
  CLASSES=("${MUTATE_ONLY}")
fi

MIN="${MUTATE_MIN:-95}"
FAILED=0

for class in "${CLASSES[@]}"; do
  echo "::group::mutate ${class}"
  if ! vendor/bin/pest --mutate --min="${MIN}" --class="${class}"; then
    echo "::error::Mutation score below ${MIN}% for ${class}"
    FAILED=1
  fi
  echo "::endgroup::"
done

if [[ "${FAILED}" -ne 0 ]]; then
  echo "One or more classes scored below ${MIN}%."
  exit 1
fi

echo "All ${#CLASSES[@]} classes scored >= ${MIN}%."
