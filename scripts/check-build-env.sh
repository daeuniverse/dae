#!/usr/bin/env bash
# Single-owner gate for build inputs that CI must not restate.
#
# GOEXPERIMENT is owned by the Makefile (DEFAULT_GOEXPERIMENT). CI and
# the Dockerfile read it with `make -s print-goexperiment`. Before this gate
# the release workflow built with a 4-tuple while Docker and local builds used
# a 2-tuple, so "reproduce the released performance in a container" was
# structurally impossible (dae_docker_repro.log).
#
# The geo data pins live in scripts/fetch-geo-data.sh. The Dockerfile
# cannot call that script, so its ARG defaults are cross-checked here instead
# of being left to drift.
#
# Usage: scripts/check-build-env.sh
# Exit: 0 clean; 1 a duplicated/drifted build input was found.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

fail=0

# --- 1. GOEXPERIMENT must exist in exactly one place (the Makefile). ---------
# An *assignment* is what forks the build configuration, so this matches
# `GOEXPERIMENT=` / `GOEXPERIMENT:` (YAML key, `export`, `ENV`, `ARG`). Naming
# the variable in prose or in a step name is allowed — a gate that also forbids
# documenting the rule would only produce worse comments.
GOEXPERIMENT_ASSIGN='(^|[^A-Za-z0-9_])GOEXPERIMENT[[:space:]]*[=:]'
if hits="$(git grep -n -E "$GOEXPERIMENT_ASSIGN" -- .github Dockerfile)"; then
  echo "::error::GOEXPERIMENT must have a single owner (Makefile). Remove these assignments and read the value with 'make -s print-goexperiment':" >&2
  echo "$hits" >&2
  fail=1
fi

# --- 2. Dockerfile geo ARGs must equal the pinned values of the fetch script. -
script_pins="$(sed -n -E 's/^((GEOIP|GEOSITE)_(VERSION|SHA256))="(.*)"$/\1=\4/p' scripts/fetch-geo-data.sh)"
if [ -z "$script_pins" ]; then
  echo "::error::scripts/fetch-geo-data.sh does not declare GEOIP_VERSION/GEOIP_SHA256/GEOSITE_VERSION/GEOSITE_SHA256" >&2
  fail=1
fi

for name in GEOIP_VERSION GEOIP_SHA256 GEOSITE_VERSION GEOSITE_SHA256; do
  want="$(sed -n -E "s/^${name}=(.*)$/\1/p" <<<"$script_pins")"
  got="$(sed -n -E "s/^ARG ${name}=(.*)$/\1/p" Dockerfile)"
  if [ -z "$want" ]; then
    echo "::error::${name} is not pinned in scripts/fetch-geo-data.sh" >&2
    fail=1
    continue
  fi
  if [ "$got" != "$want" ]; then
    echo "::error::Dockerfile ARG ${name}='${got}' != scripts/fetch-geo-data.sh '${want}'" >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "build env single-owner check: OK"
echo "  GOEXPERIMENT: owned by Makefile ($(make -s print-goexperiment))"
echo "  geo pins: Dockerfile ARGs match scripts/fetch-geo-data.sh"
