#!/bin/bash
#
#  SPDX-License-Identifier: AGPL-3.0-only
#  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
#
# Usage:
#   append_license_signature.sh                add the SPDX header to every
#                                              tracked *.go file missing it
#   append_license_signature.sh <file>...      add the header to these files
#   append_license_signature.sh --check [file] report the files missing the
#                                              header and exit 1; never writes
#
# --check is what CI runs (lint.yml) on the files a pull request adds or
# modifies: 58 of the 411 tracked *.go files predate the header policy, and
# failing every PR on that backlog would only train `--no-verify`.
set -euo pipefail

SPDX_MARKER='SPDX-License-Identifier: AGPL-3.0-only'
# These paths are generated from an upstream project that owns their headers.
EXCLUDE_PATTERNS=('pkg/ebpf_internal/*' 'pkg/geodata/*')

check_only=0
if [ "${1:-}" = "--check" ]; then
  check_only=1
  shift
fi

is_excluded() {
  local path="${1#./}"
  local pattern
  for pattern in "${EXCLUDE_PATTERNS[@]}"; do
    # shellcheck disable=SC2053
    if [[ "$path" == $pattern ]]; then
      return 0
    fi
  done
  return 1
}

# Collect the target files: the explicit arguments, else every *.go file that
# is missing the marker (the original behaviour).
files=""
if [ "$#" -gt 0 ]; then
  for file in "$@"; do
    if [ ! -f "$file" ]; then
      echo "File not found: $file" >&2
      exit 1
    fi
    if is_excluded "$file"; then
      continue
    fi
    files+="$file"$'\n'
  done
else
  if ! command -v rg >/dev/null 2>&1; then
    echo "ripgrep (rg) is required" >&2
    exit 1
  fi
  set +e
  files=$(rg -F "$SPDX_MARKER" --files-without-match --glob '*.go' --glob '!pkg/ebpf_internal/**/*.go' --glob '!pkg/geodata/**/*.go' .)
  rc=$?
  set -e
  # rg exits 1 when it selects no file, i.e. every file already carries the
  # marker. Any higher exit code is a real failure and must not be swallowed.
  if [ "$rc" -gt 1 ]; then
    echo "rg failed with exit code $rc" >&2
    exit 1
  fi
fi

# Insert the specified lines to the top of each target file
insert_lines() {
  local file="$1"
  if [ -f "$file" ]; then
    # Inserting lines at the beginning of the file
    {
      echo "/*"
      echo "*  SPDX-License-Identifier: AGPL-3.0-only"
      echo "*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>"
      echo "*/"
      echo
      cat "$file"
    } >tempfile && mv tempfile "$file"
    echo "Lines inserted into $file"
  else
    echo "File not found: $file"
  fi
}

missing=0
while IFS= read -r file; do
  [ -n "$file" ] || continue
  if [ "$check_only" -eq 1 ]; then
    if grep -qF -- "$SPDX_MARKER" "$file"; then
      continue
    fi
    echo "missing SPDX header: $file"
    missing=$((missing + 1))
    continue
  fi
  insert_lines "$file"
done <<<"$files"

if [ "$check_only" -eq 1 ] && [ "$missing" -gt 0 ]; then
  echo "$missing file(s) lack '$SPDX_MARKER'; run ./hack/maintenance/append_license_signature.sh <file> to add it" >&2
  exit 1
fi
