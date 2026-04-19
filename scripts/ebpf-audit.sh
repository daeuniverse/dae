#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-build/ebpf-audit}"
CLANG_BIN="${CLANG:-clang}"
OBJDUMP_BIN="${LLVM_OBJDUMP:-llvm-objdump}"
BPF_ENDIAN_TARGET="${BPF_ENDIAN_TARGET:-bpfel}"
MAX_MATCH_SET_LEN="${MAX_MATCH_SET_LEN:-1024}"
OBJECT_PATH="${OUT_DIR}/static/tproxy_${BPF_ENDIAN_TARGET}.o"

if [[ "${EUID}" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo --preserve-env=PATH,HOME,GOCACHE,GOMODCACHE,GOPATH,GOEXPERIMENT,CLANG,LLVM_OBJDUMP,BPF_ENDIAN_TARGET,MAX_MATCH_SET_LEN "$0" "$@"
  fi
  echo "root privileges are required to load eBPF programs" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
rm -rf "${OUT_DIR:?}"/*

mkdir -p "${OUT_DIR}/static" "${OUT_DIR}/bpftool/programs" "${OUT_DIR}/bpftool/maps"

if ! command -v bpftool >/dev/null 2>&1; then
  echo "bpftool is required" >&2
  exit 1
fi

if ! command -v "${CLANG_BIN}" >/dev/null 2>&1; then
  echo "clang compiler is required: ${CLANG_BIN}" >&2
  exit 1
fi

if ! command -v "${OBJDUMP_BIN}" >/dev/null 2>&1; then
  echo "llvm-objdump is required" >&2
  exit 1
fi

{
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "uname=$(uname -a)"
  echo "bpftool=$(bpftool version 2>&1 | tr '\n' ' ')"
  echo "clang=$(${CLANG_BIN} --version | head -n1)"
  echo "llvm-objdump=$(${OBJDUMP_BIN} --version | head -n1)"
  echo "go=$(go version)"
} > "${OUT_DIR}/environment.txt"

if [[ -f /sys/kernel/btf/vmlinux ]]; then
  echo "kernel_btf=/sys/kernel/btf/vmlinux" >> "${OUT_DIR}/environment.txt"
else
  echo "kernel_btf=missing" >> "${OUT_DIR}/environment.txt"
fi

git submodule update --init
go generate ./common/consts/ebpf.go

if ! "${CLANG_BIN}" -O2 -g -target "${BPF_ENDIAN_TARGET}" -Wall -Werror \
  -DMAX_MATCH_SET_LEN="${MAX_MATCH_SET_LEN}" \
  -c control/kern/tproxy.c -o "${OBJECT_PATH}" \
  > "${OUT_DIR}/static/compile.stdout.txt" 2> "${OUT_DIR}/static/compile.stderr.txt"; then
  exit 1
fi

"${OBJDUMP_BIN}" -h "${OBJECT_PATH}" > "${OUT_DIR}/static/object-sections.txt"
"${OBJDUMP_BIN}" -t "${OBJECT_PATH}" > "${OUT_DIR}/static/object-symbols.txt"
"${OBJDUMP_BIN}" -d --no-show-raw-insn "${OBJECT_PATH}" > "${OUT_DIR}/static/object-disasm.txt"

bpftool feature probe kernel > "${OUT_DIR}/bpftool/feature-probe.txt" 2>&1 || true

go run ./cmd/dae-ebpf-audit \
  -object "${OBJECT_PATH}" \
  -output-dir "${OUT_DIR}" \
  -hold \
  > "${OUT_DIR}/audit.stdout.txt" 2> "${OUT_DIR}/audit.stderr.txt" &
audit_pid=$!

audit_status=0
ready=0
for _ in $(seq 1 60); do
  if [[ -f "${OUT_DIR}/audit.ready" ]]; then
    ready=1
    break
  fi
  if [[ -f "${OUT_DIR}/load-error.txt" ]]; then
    break
  fi
  if ! kill -0 "${audit_pid}" 2>/dev/null; then
    break
  fi
  sleep 1
done

if [[ "${ready}" -eq 1 && -f "${OUT_DIR}/manifest.tsv" ]]; then
  while IFS=$'\t' read -r kind name id; do
    [[ -n "${kind}" ]] || continue
    case "${kind}" in
      program)
        bpftool prog show id "${id}" > "${OUT_DIR}/bpftool/programs/${name}.show.txt" 2>&1 || true
        bpftool prog dump xlated id "${id}" > "${OUT_DIR}/bpftool/programs/${name}.xlated.txt" 2>&1 || true
        bpftool prog dump jited id "${id}" > "${OUT_DIR}/bpftool/programs/${name}.jited.txt" 2>&1 || true
        ;;
      map)
        bpftool map show id "${id}" > "${OUT_DIR}/bpftool/maps/${name}.show.txt" 2>&1 || true
        ;;
    esac
  done < "${OUT_DIR}/manifest.tsv"
else
  echo "audit process did not become ready" > "${OUT_DIR}/bpftool/dump-error.txt"
  audit_status=1
fi

if kill -0 "${audit_pid}" 2>/dev/null; then
  kill -TERM "${audit_pid}" 2>/dev/null || true
fi
wait "${audit_pid}" || audit_status=$?

if [[ "${ready}" -eq 1 && "${audit_status}" -eq 143 ]]; then
  audit_status=0
fi

exit "${audit_status}"
