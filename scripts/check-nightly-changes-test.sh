#!/usr/bin/env bash
set -euo pipefail

script=$(realpath "$(dirname "$0")/check-nightly-changes.sh")
repo=$(mktemp -d)
trap 'rm -rf "$repo"' EXIT
cd "$repo"
git init -q
git config user.email test@example.invalid
git config user.name Test

commit_at() {
  GIT_AUTHOR_DATE="$1" GIT_COMMITTER_DATE="$1" git commit -q --allow-empty -m test
}
check() {
  local expected actual timestamp
  expected="changed=$1"$'\n'"sha=$(git rev-parse HEAD)"
  timestamp=$(date --date="$2" +%s)
  actual=$(bash "$script" "$timestamp")
  if [[ "$actual" != "$expected" ]]; then
    printf 'expected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
    exit 1
  fi
}

# Before UTC+8 midnight is not today, even though it is the same UTC date.
commit_at '2026-09-23T15:59:59Z'
check false '2026-09-24T12:00:00Z'
# Midnight itself counts; this is still the previous date in UTC.
commit_at '2026-09-23T16:00:00Z'
check true '2026-09-24T12:00:00Z'
# A backdated HEAD must not hide a qualifying ancestor.
commit_at '2026-09-22T12:00:00Z'
check true '2026-09-24T12:00:00Z'
# Once UTC+8 rolls to the next day, the previous day's commits do not count.
check false '2026-09-24T16:00:00Z'
# Future-dated commits do not count before their timestamp.
commit_at '2026-09-25T12:00:00Z'
check false '2026-09-24T16:00:00Z'
check true '2026-09-25T12:00:00Z'

echo 'nightly change detection: OK (UTC+8 boundaries, non-monotonic history, future dates, pinned SHA)'
