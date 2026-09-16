#!/usr/bin/env bash
# Artifact-level assertions for the build inputs that used to be declared in
# several places (the trace build tag and GOEXPERIMENT).
#
# Audit rule: assert on the artifact (`go version -m`), never on intent
# (.build_tags, workflow env). Both directions are asserted so a bogus
# TRACE_UNSUPPORTED_GOARCH entry cannot mask a real trace build:
#   * GOARCH not in TRACE_UNSUPPORTED_GOARCH -> binary HAS `-tags=trace`
#   * GOARCH in TRACE_UNSUPPORTED_GOARCH     -> binary has NO `-tags=trace`
#   * binary GOEXPERIMENT == `make -s print-goexperiment`
#   * .build_tags (what the build actually passed to `go build`) agrees with
#     the binary in both cases
#
# Usage: scripts/check-artifact-build-env.sh <binary> [goarch]
# Exit: 0 all assertions hold; 1 otherwise.
set -euo pipefail

bin="${1:-}"
goarch="${2:-$(go env GOARCH)}"

if [ -z "$bin" ] || [ ! -f "$bin" ]; then
  echo "Usage: $0 <binary> [goarch]" >&2
  exit 2
fi
if [ ! -f .build_tags ]; then
  echo "::error::.build_tags is missing; the 'ebpf' target writes it, so run 'make' first" >&2
  exit 1
fi

info="$(go version -m "$bin")"
actual_tags="$(awk -F'\t' '$2 == "build" && $3 ~ /^-tags=/ { sub(/^-tags=/, "", $3); print $3 }' <<<"$info")"
actual_exp="$(awk -F'\t' '$2 == "build" && $3 ~ /^GOEXPERIMENT=/ { sub(/^GOEXPERIMENT=/, "", $3); print $3 }' <<<"$info")"
declared_tags="$(tr -d '[:space:]' < .build_tags)"

expected_exp="$(make -s print-goexperiment)"
unsupported="$(make -s print-trace-unsupported)"

trace_expected=present
for arch in $unsupported; do
  if [ "$arch" = "$goarch" ]; then
    trace_expected=absent
  fi
done

echo "artifact build-env assertion: $bin"
echo "  goarch=$goarch trace_expected=$trace_expected"
echo "  binary -tags='$actual_tags'  .build_tags='$declared_tags'"
echo "  binary GOEXPERIMENT='$actual_exp'  make print-goexperiment='$expected_exp'"

fail=0

# --- trace build tag: present/absent, both directions ------------------------
if [ "$trace_expected" = present ]; then
  case ",$actual_tags," in
  *,trace,*) ;;
  *)
    echo "::error::GOARCH=$goarch is not declared in TRACE_UNSUPPORTED_GOARCH ($unsupported) but $bin was built without the 'trace' tag" >&2
    fail=1
    ;;
  esac
  if [ "$declared_tags" != trace ]; then
    echo "::error::.build_tags='$declared_tags' but GOARCH=$goarch must build with the 'trace' tag" >&2
    fail=1
  fi
else
  case ",$actual_tags," in
  *,trace,*)
    echo "::error::GOARCH=$goarch is declared in TRACE_UNSUPPORTED_GOARCH ($unsupported) but $bin was built with the 'trace' tag" >&2
    fail=1
    ;;
  esac
  if [ -n "$declared_tags" ]; then
    echo "::error::.build_tags='$declared_tags' but GOARCH=$goarch is declared trace-unsupported (expected an empty tag set plus the WARNING printed by 'make ebpf')" >&2
    fail=1
  fi
fi

# --- GOEXPERIMENT ------------------------------------------------------------
if [ "$actual_exp" != "$expected_exp" ]; then
  echo "::error::$bin GOEXPERIMENT='$actual_exp' differs from 'make -s print-goexperiment' ('$expected_exp')" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "artifact build-env assertion: OK"
