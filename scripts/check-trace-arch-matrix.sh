#!/usr/bin/env bash
# Ledger gate for the "dae trace is not built for this GOARCH" declaration.
#
# TRACE_UNSUPPORTED_GOARCH is a checked-in claim about what the toolchain can do.
# Without a gate it rots in both directions:
#   * an architecture listed there that CAN generate trace ships a crippled
#     binary for no reason (its `dae trace` diagnostics are silently missing);
#   * an architecture removed from the list without proof turns a shipped
#     degradation into a failed release leg (or, worse, gets re-added only
#     because someone remembered).
# So this runs the real generator for every listed architecture (each must FAIL)
# and once for a control architecture (must SUCCEED — otherwise a missing clang
# would make every architecture "unsupported" and the gate would pass vacuously).
#
# The invocation mirrors the Makefile's `ebpf` recipe (same bpf2go directive,
# BPF_TARGET/BPF_CFLAGS/BPF_STRIP_FLAG, and the same "the architecture is a BPF
# target, not a Go build target" split — see generate() below). CI passes
# CLANG=clang-<version>.
#
# Usage: scripts/check-trace-arch-matrix.sh [control-goarch]
# Exit: 0 ledger matches reality; 1 otherwise.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

unsupported="$(make -s print-trace-unsupported)"
control="${1:-$(go env GOARCH)}"

if [ -z "$unsupported" ]; then
  echo "::error::TRACE_UNSUPPORTED_GOARCH is empty; refusing to run (the Makefile fail-closed path would then break every release leg that cannot generate trace)" >&2
  exit 1
fi

for arch in $unsupported; do
  if [ "$arch" = "$control" ]; then
    echo "::error::control architecture $control is also listed in TRACE_UNSUPPORTED_GOARCH; pass a supported architecture as the argument" >&2
    exit 1
  fi
done

CLANG_BIN="${CLANG:-${BPF_CLANG:-clang}}"
if ! command -v "$CLANG_BIN" >/dev/null 2>&1; then
  echo "::error::compiler '$CLANG_BIN' not found; the ledger cannot be verified" >&2
  exit 1
fi
STRIP_BIN="${STRIP:-llvm-strip}"
if STRIP_PATH="$(command -v "$STRIP_BIN" 2>/dev/null)"; then
  export BPF_STRIP_FLAG="-strip=${STRIP_PATH}"
else
  export BPF_STRIP_FLAG="-no-strip"
fi
export BPF_CLANG="$CLANG_BIN"
export BPF_CFLAGS="${BPF_CFLAGS:--O2 -Wall -Werror -DMAX_MATCH_SET_LEN=${MAX_MATCH_SET_LEN:-1024}}"
export BPF_TARGET="${TARGET:-bpfel,bpfeb}"

# generate <arch> <log>; returns the generator's status (output kept in the log).
#
# The architecture is the *BPF target* — it selects which __TARGET_ARCH_* layout
# bpf_tracing.h expands — not the Go build target. So it is passed through
# BPF_TRACE_TARGET only and GOARCH is deliberately left alone, exactly as the
# Makefile's `ebpf` recipe does (Makefile unsets GOOS/GOARCH/GOARM inside the
# recipe for the same reason). With GOARCH set, `go run .../cmd/bpf2go`
# cross-builds bpf2go for that architecture and then executes it, which on a
# runner without binfmt emulation dies with "exec format error" for every
# architecture other than the host's — and on a host WITH binfmt (WSL2 registers
# qemu-*) succeeds through emulation. That is the shape that made this gate look
# green locally while it was red in CI, so classify_failure() below treats the
# exec-format failure as this gate's own fault rather than as evidence.
generate() {
  local arch="$1" log="$2"
  BPF_TRACE_TARGET="$arch" go generate ./trace/trace.go >"$log" 2>&1
}

# last_output_line <log>: the last non-empty line, always non-empty itself.
last_output_line() {
  local line
  line="$(grep -vE '^[[:space:]]*$' "$1" 2>/dev/null | tail -n 1 || true)"
  if [ -z "$line" ]; then
    line="<the generator produced no output at all>"
  fi
  printf '%s' "${line:0:160}"
}

# classify_failure <log>: prints "<kind><TAB><reason>" for a failed generation.
#
# The gate is only evidence when the generator actually ran and said why it
# failed, so three outcomes are distinguished:
#   ran     - bpf2go or clang reported a diagnostic; the architecture really is
#             the limitation, and the diagnostic is the proof of it.
#   env     - the generator could not be executed in this environment
#             ("exec format error" / "cannot execute binary file"); this says
#             nothing about the architecture and is a failure of the gate. The
#             offending line is quoted so the reason names itself.
#   unknown - it ran but produced nothing attributable; a failure nobody can
#             read cannot justify a declaration either, so it is also a fault of
#             the gate. The reason falls back to the last output line, so a
#             report can never come out as an empty pair of parentheses.
classify_failure() {
  local log="$1" reason
  reason="$(grep -m1 -E 'exec format error|cannot execute binary file' "$log" 2>/dev/null || true)"
  if [ -n "$reason" ]; then
    printf 'env\t%s' "${reason:0:160}"
    return 0
  fi
  reason="$(grep -m1 -E 'unsupported target|no compiler specified|error:' "$log" 2>/dev/null || true)"
  if [ -n "$reason" ]; then
    printf 'ran\t%s' "${reason:0:160}"
    return 0
  fi
  printf 'unknown\t%s' "$(last_output_line "$log")"
}

fail=0
for arch in $unsupported; do
  log="/tmp/trace-arch-${arch}.log"
  if generate "$arch" "$log"; then
    echo "::error::GOARCH=$arch is declared in TRACE_UNSUPPORTED_GOARCH but its trace program GENERATED successfully; remove it from the list (or keep it only if the declaration is still wanted, which now needs a different justification)" >&2
    tail -5 "$log" >&2
    fail=1
  else
    IFS=$'\t' read -r kind reason <<<"$(classify_failure "$log")"
    if [ "$kind" != "ran" ]; then
      echo "::error::GOARCH=$arch: the trace generator reported no architecture limitation ($kind: $reason); this is a failure of the gate, not evidence that $arch is unsupported, so the declaration stays unverified here" >&2
      fail=1
    else
      echo "trace lint: GOARCH=$arch cannot generate trace, as declared: $reason"
      tail -3 "$log" >&2
    fi
  fi
done

control_log="/tmp/trace-arch-${control}.log"
if generate "$control" "$control_log"; then
  echo "trace lint: control GOARCH=$control generates trace (so a failure above is a real per-architecture limitation, not a broken environment)"
else
  IFS=$'\t' read -r kind reason <<<"$(classify_failure "$control_log")"
  echo "::error::control GOARCH=$control must generate trace but failed ($kind: $reason); the ledger cannot be trusted" >&2
  tail -10 "$control_log" >&2
  fail=1
fi

# Coverage direction: every GOARCH that the release matrix and the Docker
# platforms can build must have an explicit decision. One that is absent from
# TRACE_UNSUPPORTED_GOARCH has to generate trace; if it does not, the fail-closed
# build would break that release leg, which is how mips, arm and s390x were each
# found only after the tag was already being dropped silently.
matrix_archs=$(
  {
    # goarch: [ a, b, c ]  and  goarch: x  (include entries)
    sed -n 's/.*goarch: *\[\(.*\)\].*/\1/p; s/.*goarch: *\([a-z0-9][a-z0-9]*\).*/\1/p' \
      .github/workflows/release.yml .github/workflows/prerelease.yml .github/workflows/seed-build.yml 2>/dev/null
    # platforms: linux/arm/v7,linux/arm64,linux/amd64,linux/386
    sed -n 's/.*platforms: *//p' .github/workflows/docker.yml 2>/dev/null \
      | tr ',' '\n' | sed 's#^linux/##; s#/v[0-9]*$##'
  } | tr ' ,' '\n\n' | sed 's/[^a-z0-9]//g' | sed '/^$/d' | sort -u
)
if [ -z "$matrix_archs" ]; then
  echo "::error::could not derive the architecture matrix from the workflows; the coverage check cannot run" >&2
  fail=1
else
  for arch in $matrix_archs; do
    case " $unsupported " in
      *" $arch "*) continue ;;
    esac
    log="/tmp/trace-arch-matrix-${arch}.log"
    if generate "$arch" "$log"; then
      echo "trace lint: matrix GOARCH=$arch generates trace (no declaration needed)"
    else
      IFS=$'\t' read -r kind reason <<<"$(classify_failure "$log")"
      if [ "$kind" = "env" ]; then
        echo "::error::GOARCH=$arch: the trace generator could not be executed in this environment ($reason); this is a failure of the gate, not evidence about the architecture" >&2
      else
        echo "::error::GOARCH=$arch is built by the release matrix or the Docker platforms but cannot generate the trace program, and it is not declared in TRACE_UNSUPPORTED_GOARCH; the fail-closed build would fail that leg ($reason)" >&2
      fi
      tail -5 "$log" >&2
      fail=1
    fi
  done
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "trace architecture ledger: OK (declared trace-less: $(echo $unsupported | tr ' ' ','), control: $control, matrix: $(echo $matrix_archs | tr '\n' ','))"
