#!/usr/bin/env bash
set -euo pipefail

OUTDIR="${1:-${TMPDIR:-/tmp}/dae-control-memory}"
IMAGE="${GO_IMAGE:-golang:1.26}"
BENCH_REGEX='BenchmarkDnsCache_COW_GetPackedResponse$|BenchmarkDnsCache_COW_Update$|BenchmarkDnsController_UpdateDnsCacheTtl_Replace$|BenchmarkDnsController_OnDnsCacheEvicted_Spill$|BenchmarkStaleDnsSideEffects_SharedIp$|BenchmarkDnsController_EvictLRUIfFull$'
PROFILE_BENCH='BenchmarkDnsController_UpdateDnsCacheTtl_Replace$'

mkdir -p "${OUTDIR}"

run_local() {
    go test ./control -run '^$' -bench "${BENCH_REGEX}" -benchmem -count=1 | tee "${OUTDIR}/bench.txt"
    go test -c -o "${OUTDIR}/control.test" ./control
    "${OUTDIR}/control.test" \
        -test.run '^$' \
        -test.bench "${PROFILE_BENCH}" \
        -test.benchmem \
        -test.count=1 \
        -test.memprofile "${OUTDIR}/update_replace.mem.out" \
        -test.cpuprofile "${OUTDIR}/update_replace.cpu.out"
    go tool pprof -top "${OUTDIR}/control.test" "${OUTDIR}/update_replace.mem.out" | tee "${OUTDIR}/update_replace.mem.top.txt"
}

run_docker() {
    docker run --rm \
        -v "$(pwd)":/src \
        -v "${OUTDIR}":/out \
        -w /src \
        "${IMAGE}" \
        bash -lc "
            set -euo pipefail
            export PATH=/usr/local/go/bin:\$PATH
            go test ./control -run '^$' -bench '${BENCH_REGEX}' -benchmem -count=1 | tee /out/bench.txt
            go test -c -o /out/control.test ./control
            /out/control.test \
                -test.run '^$' \
                -test.bench '${PROFILE_BENCH}' \
                -test.benchmem \
                -test.count=1 \
                -test.memprofile /out/update_replace.mem.out \
                -test.cpuprofile /out/update_replace.cpu.out
            go tool pprof -top /out/control.test /out/update_replace.mem.out | tee /out/update_replace.mem.top.txt
        "
}

if command -v go >/dev/null 2>&1; then
    if go version >/dev/null 2>&1; then
        run_local
    elif command -v docker >/dev/null 2>&1; then
        run_docker
    else
        echo "go is present in PATH but not runnable, and docker is unavailable" >&2
        exit 1
    fi
elif command -v docker >/dev/null 2>&1; then
    run_docker
else
    echo "go or docker is required to profile control memory behavior" >&2
    exit 1
fi

cat <<EOF
Wrote control memory artifacts to:
  ${OUTDIR}/bench.txt
  ${OUTDIR}/control.test
  ${OUTDIR}/update_replace.mem.out
  ${OUTDIR}/update_replace.cpu.out
  ${OUTDIR}/update_replace.mem.top.txt
EOF
