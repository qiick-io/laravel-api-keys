#!/usr/bin/env bash
# Enforce pest --mutate --min=95 on every runtime class in src/, one class at a time
# (a combined --class CSV can hide a weak class behind a high overall score).
#
# The class list is derived from src/, so a new class is gated automatically.
# Excluded by docs/decisions/2026-11-24-one-point-zero-checklist.md: interfaces
# (no executable code), enums without methods, and the Testing namespace.
#
# MUTATE_SHARD=i/n runs the i-th of n slices (CI shards). CacheAttemptLimiter's store
# tests need live Redis and Memcached: it runs only when API_KEYS_LIMITER_STORE=both (its own
# CI job) and is skipped everywhere else. MUTATE_ONLY=<FQCN> runs a single class.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CLASSES=()

while IFS= read -r file; do
  relative="${file#src/}"

  case "${relative}" in
    Testing/*|Contracts/*) continue ;;
  esac

  declaration="$(grep -m1 -E '^(final |abstract )?(readonly )?(class|interface|enum|trait) ' "${file}" || true)"

  case "${declaration}" in
    ''|*interface\ *|*trait\ *) continue ;;
    *enum\ *)
      grep -q 'function ' "${file}" || continue
      ;;
  esac

  class="Qiick\\ApiKeys\\$(echo "${relative%.php}" | tr '/' '\\')"

  if [[ "${class}" == 'Qiick\ApiKeys\CacheAttemptLimiter' && "${API_KEYS_LIMITER_STORE:-}" != 'both' ]]; then
    continue
  fi

  CLASSES+=("${class}")
done < <(find src -name '*.php' | LC_ALL=C sort)

if [[ -n "${MUTATE_ONLY:-}" ]]; then
  CLASSES=("${MUTATE_ONLY}")
fi

if [[ -n "${MUTATE_SHARD:-}" ]]; then
  shard_index="${MUTATE_SHARD%/*}"
  shard_count="${MUTATE_SHARD#*/}"
  SHARD_CLASSES=()

  for position in "${!CLASSES[@]}"; do
    if (( position % shard_count == shard_index - 1 )); then
      SHARD_CLASSES+=("${CLASSES[$position]}")
    fi
  done

  CLASSES=("${SHARD_CLASSES[@]}")
fi

if [[ "${MUTATE_LIST:-}" == '1' ]]; then
  printf '%s\n' "${CLASSES[@]}"
  exit 0
fi

MIN="${MUTATE_MIN:-95}"
FAILED=0

OUTPUT="$(mktemp)"
trap 'rm -f "${OUTPUT}"' EXIT

for class in "${CLASSES[@]}"; do
  echo "::group::mutate ${class}"
  if vendor/bin/pest --mutate --min="${MIN}" --class="${class}" 2>&1 | tee "${OUTPUT}"; [[ "${PIPESTATUS[0]}" -ne 0 ]]; then
    # A class with no mutable code (a value object of promoted properties) has
    # nothing to prove; Pest reports it as 0%, so it is passed explicitly.
    if grep -q 'No mutations created' "${OUTPUT}"; then
      echo "No mutable code in ${class}."
    else
      echo "::error::Mutation score below ${MIN}% for ${class}"
      FAILED=1
    fi
  fi
  echo "::endgroup::"
done

if [[ "${FAILED}" -ne 0 ]]; then
  echo "One or more classes scored below ${MIN}%."
  exit 1
fi

echo "All ${#CLASSES[@]} classes scored >= ${MIN}%."
