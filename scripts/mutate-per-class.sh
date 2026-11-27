#!/usr/bin/env bash
# Enforce pest --mutate --min=95 on every runtime class in src/, one class at a time
# (a combined --class CSV can hide a weak class behind a high overall score).
#
# Each type has its own PSR-4 file. Pass that path to Pest because its class
# selector also matches name prefixes and cannot target enums with methods.
# Excluded by docs/decisions/2026-11-24-one-point-zero-checklist.md: interfaces
# (no executable code), enums without methods, and the Testing namespace.
#
# MUTATE_SHARD=i/n runs the i-th of n slices (CI shards). CacheAttemptLimiter's store
# tests need live Redis and Memcached: it runs only when API_KEYS_LIMITER_STORE=both (its own
# CI job) and is skipped everywhere else. MUTATE_ONLY=<FQCN> runs a single class.
# MUTATE_SCOPE=changed uses MUTATE_CLASSES, a JSON list of changed source paths.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

case "${MUTATE_SCOPE:-all}" in
  all) ;;
  changed)
    CHANGED_FILES="$(node -e '
      const paths = JSON.parse(process.argv[1]);
      if (!Array.isArray(paths) || paths.some(path => typeof path !== "string" || path.includes("\n"))) {
        throw new TypeError("MUTATE_CLASSES must be a JSON list of single-line paths.");
      }
      console.log(paths.join("\n"));
    ' "${MUTATE_CLASSES:-[]}")"
    ;;
  *) echo 'MUTATE_SCOPE must be all or changed.' >&2; exit 1 ;;
esac

CLASSES=()
FILES=()

while IFS= read -r file; do
  relative="${file#src/}"

  case "${relative}" in
    Testing/*) continue ;;
  esac

  declaration="$(grep -m1 -E '^(final |abstract )?(readonly )?(class|interface|enum|trait) ' "${file}" || true)"

  case "${declaration}" in
    '') echo "Unclassified source file: ${file}" >&2; exit 1 ;;
    *interface\ *) continue ;;
    *enum\ *)
      grep -q 'function ' "${file}" || continue
      ;;
  esac

  type_path="${relative%.php}"
  class="Qiick\\ApiKeys\\${type_path//\//\\}"

  if [[ -n "${MUTATE_ONLY:-}" && "${class}" != "${MUTATE_ONLY}" ]]; then
    continue
  fi

  if [[ "${MUTATE_SCOPE:-all}" == 'changed' ]] && ! grep -Fxq -- "${file}" <<< "${CHANGED_FILES}"; then
    continue
  fi

  if [[ "${class}" == 'Qiick\ApiKeys\CacheAttemptLimiter' && "${API_KEYS_LIMITER_STORE:-}" != 'both' ]]; then
    continue
  fi

  CLASSES+=("${class}")
  FILES+=("${file}")
done < <(find src -name '*.php' | LC_ALL=C sort)

if [[ -n "${MUTATE_ONLY:-}" && "${#CLASSES[@]}" == '0' ]]; then
  echo "Unknown mutation target for the selected scope and stores: ${MUTATE_ONLY}" >&2
  exit 1
fi

if [[ "${MUTATE_SCOPE:-all}" == 'all' && "${#CLASSES[@]}" == '0' ]]; then
  echo 'No source types found for the full mutation gate.' >&2
  exit 1
fi

POSITIONS=("${!CLASSES[@]}")

if [[ -n "${MUTATE_SHARD:-}" ]]; then
  shard_index="${MUTATE_SHARD%/*}"
  shard_count="${MUTATE_SHARD#*/}"
  POSITIONS=()

  for position in "${!CLASSES[@]}"; do
    if (( position % shard_count == shard_index - 1 )); then
      POSITIONS+=("${position}")
    fi
  done
fi

if [[ "${MUTATE_LIST:-}" == '1' ]]; then
  for position in "${POSITIONS[@]}"; do
    printf '%s\n' "${CLASSES[$position]}"
  done
  exit 0
fi

FAILED=0

OUTPUT="$(mktemp)"
trap 'rm -f "${OUTPUT}"' EXIT

for position in "${POSITIONS[@]}"; do
  class="${CLASSES[$position]}"
  file="${FILES[$position]}"
  echo "::group::mutate ${class}"
  if ! vendor/bin/pest --mutate --min=95 --path="${file}" 2>&1 | tee "${OUTPUT}"; then
    # A class with no mutable code (a value object of promoted properties) has
    # nothing to prove; Pest reports it as 0%, so it is passed explicitly.
    if grep -q 'No mutations created' "${OUTPUT}"; then
      echo "No mutable code in ${class}."
    else
      echo "::error::Mutation gate failed for ${class}"
      FAILED=1
    fi
  fi
  echo "::endgroup::"
done

if [[ "${FAILED}" -ne 0 ]]; then
  echo "One or more mutation targets failed the 95% gate."
  exit 1
fi

echo "Mutation gate passed for ${#POSITIONS[@]} targets (95% where Pest generates mutations)."
