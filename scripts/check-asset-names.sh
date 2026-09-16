#!/usr/bin/env bash
# Release asset names have exactly one source: install/friendly-filenames.json.
#
# The matrix legs for riscv64 (base, rva20u64, rva22u64, rva23u64) all
# resolved to the single key "linux-riscv64", so three of the four legs
# published the same asset name and the declared rva22/rva23 builds were never
# produced under a distinguishable name. Two failure modes are asserted here:
#   1. two keys mapping to the same friendlyName (duplicate asset names);
#   2. an entry whose friendlyName is missing/empty/non-string (the per-leg
#      `jq -er` lookup in the workflows could then not fail loudly on a
#      missing key and would publish "dae-null").
# Every matrix leg additionally asserts its own key resolves with `jq -er`;
# that per-leg assertion is what makes this preflight complete without
# duplicating the build matrix in a second place.
#
# Usage: scripts/check-asset-names.sh [install/friendly-filenames.json]
# Exit: 0 unique and resolvable; 1 otherwise.
set -euo pipefail

json="${1:-install/friendly-filenames.json}"

if ! command -v jq >/dev/null 2>&1; then
  echo "::error::jq is required by $0" >&2
  exit 1
fi
if [ ! -f "$json" ]; then
  echo "::error::$json not found" >&2
  exit 1
fi

# --- 2. every entry must resolve to a non-empty string -----------------------
if ! jq -e 'length > 0 and all(to_entries[]; (.key != "") and (.value.friendlyName | type == "string") and (.value.friendlyName != ""))' "$json" >/dev/null; then
  echo "::error::$json has entries whose friendlyName is missing, empty or not a string:" >&2
  jq -r 'to_entries[] | select((.value.friendlyName // "") == "" or (.value.friendlyName | type != "string")) | "  \(.key)"' "$json" >&2
  exit 1
fi

# --- 1. friendlyName values must be unique -----------------------------------
dupes="$(jq -r '[.[].friendlyName] | group_by(.) | map(select(length > 1)) | map(.[0]) | .[]' "$json")"
if [ -n "$dupes" ]; then
  echo "::error::$json maps several matrix keys to the same friendlyName (duplicate release asset names):" >&2
  while IFS= read -r name; do
    printf '  %s <- %s\n' "$name" "$(jq -r --arg n "$name" '[to_entries[] | select(.value.friendlyName == $n) | .key] | join(", ")' "$json")" >&2
  done <<<"$dupes"
  exit 1
fi

echo "asset name preflight: OK ($(jq -r 'length' "$json") keys, all unique and resolvable)"
jq -r 'to_entries[] | "  \(.key) -> \(.value.friendlyName)"' "$json"
