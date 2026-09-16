#!/usr/bin/env bash
# Fetch the pinned geo data used by the release, daily and container builds.
#
# Both files used to be downloaded from `releases/latest/download`,
# which makes a rebuild of the same dae tag non-reproducible and unverifiable.
# They are now pinned by upstream release tag and verified with `sha256sum -c`
# (fail-closed: a mismatch aborts the build).
#
# The digests were cross-checked against two independent upstream sources for
# the pinned tags: the GitHub Releases API asset `digest` field and the
# upstream `<asset>.sha256sum` sidecar published in the same release.
#
# Usage: scripts/fetch-geo-data.sh <destdir>
# Exit: 0 files present and verified; 1 download or checksum failure.
set -euo pipefail

GEOIP_VERSION="202609050329"
GEOIP_SHA256="1cba1f0982cf62502fa079c66047c3d0c608196da5b3305671e68f60e917a482"
GEOSITE_VERSION="20260908094002"
GEOSITE_SHA256="35ed26a24cafa1256bd7261414224b7bcef5c944cea7760e172b030a8b266450"

GEOIP_URL="https://github.com/v2fly/geoip/releases/download/${GEOIP_VERSION}/geoip.dat"
GEOSITE_URL="https://github.com/v2fly/domain-list-community/releases/download/${GEOSITE_VERSION}/dlc.dat"

dest="${1:-}"
if [ -z "$dest" ]; then
  echo "Usage: $0 <destdir>" >&2
  exit 2
fi
mkdir -p "$dest"

fetch() {
  local url="$1" out="$2" want="$3"
  curl --fail --location --silent --show-error --retry 3 -o "$out" "$url"
  printf '%s  %s\n' "$want" "$out" >"${out}.sha256"
  if ! sha256sum -c "${out}.sha256"; then
    echo "::error::sha256 mismatch for ${out}; expected ${want} from ${url} (the pinned geo data version no longer matches its digest)" >&2
    exit 1
  fi
  rm -f "${out}.sha256"
}

fetch "$GEOIP_URL" "${dest}/geoip.dat" "$GEOIP_SHA256"
fetch "$GEOSITE_URL" "${dest}/geosite.dat" "$GEOSITE_SHA256"

echo "geo data: geoip=${GEOIP_VERSION} geosite=${GEOSITE_VERSION} verified in ${dest}"
