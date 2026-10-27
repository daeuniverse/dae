#!/usr/bin/env bash
# Optional Unix timestamp makes the UTC+8 midnight boundary reproducible.
set -euo pipefail

now=${1:-$(date +%s)}
day=$(TZ=Asia/Shanghai date --date="@$now" +%F)
start=$(date --date="$day 00:00:00 +0800" +%s)
sha=$(git rev-parse HEAD)
# Do not stop at an older commit: commit timestamps need not be monotonic.
commit=$(git log --since-as-filter="@$start" --until="@$now" -1 --format=%H "$sha")
changed=false
if [[ -n "$commit" ]]; then
  changed=true
fi
printf 'changed=%s\nsha=%s\n' "$changed" "$sha"
