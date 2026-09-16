#
#  SPDX-License-Identifier: AGPL-3.0-only
#  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
#

# The development version of clang is distributed as the 'clang' binary,
# while stable/released versions have a version number attached.
# Pin the default clang to a stable version.
CLANG ?= clang
STRIP ?= llvm-strip
CFLAGS := -O2 -Wall -Werror $(CFLAGS)
TARGET ?= bpfel,bpfeb
OUTPUT ?= dae
MAX_MATCH_SET_LEN ?= 1024
CFLAGS := -DMAX_MATCH_SET_LEN=$(MAX_MATCH_SET_LEN) $(CFLAGS)
# Single owner of the GOEXPERIMENT set used to build released artifacts.
# CI must not restate this value: read it with `make -s print-goexperiment`
# (scripts/check-build-env.sh rejects any copy under .github/ or Dockerfile).
DEFAULT_GOEXPERIMENT := newinliner,simd,heapminimum512kib,randomizedheapbase64
GOEXPERIMENT_MERGED := $(shell printf '%s\n' "$(DEFAULT_GOEXPERIMENT),$(GOEXPERIMENT)" | tr ',' '\n' | sed '/^$$/d' | awk '!seen[$$0]++' | paste -sd, -)
export GOEXPERIMENT := $(GOEXPERIMENT_MERGED)
NOSTRIP ?= n
STRIP_PATH := $(shell command -v $(STRIP) 2>/dev/null)
BUILD_TAGS_FILE := .build_tags
ifeq ($(strip $(NOSTRIP)),y)
	STRIP_FLAG := -no-strip
else ifeq ($(wildcard $(STRIP_PATH)),)
	STRIP_FLAG := -no-strip
else
	STRIP_FLAG := -strip=$(STRIP_PATH)
endif

GOARCH ?= $(shell go env GOARCH)

# Single owner of the "dae trace is not built for this GOARCH" declaration.
# An arch not listed here must build trace or fail loudly: a silent trace-less
# build ships a binary whose `dae trace` diagnostics are missing with no signal.
# CI asserts the built artifact against this list
# (scripts/check-artifact-build-env.sh), re-verifies that every listed arch
# really cannot generate trace (scripts/check-trace-arch-matrix.sh) and reads
# the list with `make -s print-trace-unsupported`.
# Measured on 2026-09-10, so nothing is listed on faith:
#   mips    -> bpf2go fails with `Error: no compiler specified`; with -cc set,
#              clang fails with `no member named 'regs' in 'struct pt_regs'`
#              (bpf_tracing.h selects the mips pt_regs layout while the vendored
#              vmlinux.h from the dae_bpf_headers submodule falls back to x86)
#   mips64, mips64le, mipsle -> bpf2go: unsupported target
# `gen.FindTarget()` accepting an architecture is NOT evidence that its trace
# program compiles: do not move mips out of this list on that basis alone.
# Reproducible probe (needs clang and the headers submodule). The architecture is
# the BPF target, NOT the Go build target: setting GOARCH makes `go generate`
# cross-build the bpf2go tool itself and then fail to exec it on the host
# ("exec format error"), which reads as "this architecture cannot generate
# trace". This is the exact mistake scripts/check-trace-arch-matrix.sh made.
#   BPF_TRACE_TARGET=<arch> BPF_CLANG=clang go generate ./trace/trace.go
# or, for the whole ledger: ./scripts/check-trace-arch-matrix.sh
# Architectures that build without the 'trace' tag, measured with the same
# generator the build uses:
#   mips/mipsle/mips64/mips64le  unsupported target (and mips: no 'regs' in struct pt_regs)
#   arm                          no member named 'uregs' in 'struct pt_regs'
#   s390x                        unknown type name 'user_pt_regs'
# Every other GOARCH must generate the trace program; the build fails instead of
# silently dropping the tag. A GOARCH that appears in the release matrix or in the
# Docker platforms but cannot generate trace belongs in this list, and
# scripts/check-trace-arch-matrix.sh verifies exactly that in both directions.
TRACE_UNSUPPORTED_GOARCH ?= arm mips mips64 mips64le mipsle s390x
TRACE_UNSUPPORTED_THIS_ARCH := $(filter $(GOARCH),$(TRACE_UNSUPPORTED_GOARCH))

# Do NOT remove the line below. This line is for CI.
# CI passes GOMODCACHE in the build step environment; it must not rewrite this
# file in place (a rewritten Makefile no longer matches the release tag).
#export GOMODCACHE=$(PWD)/go-mod

# Get version from .git.
date=$(shell git log -1 --format="%cd" --date=short | sed s/-//g)
count=$(shell git rev-list --count HEAD)
commit=$(shell git rev-parse --short HEAD)
ifeq ($(wildcard .git/.),)
	VERSION ?= unstable-0.nogit
else
	VERSION ?= unstable-$(date).r$(count).$(commit)
endif

BUILD_ARGS := -trimpath -ldflags "-s -w -X github.com/daeuniverse/dae/cmd.Version=$(VERSION) -X github.com/daeuniverse/dae/common/consts.MaxMatchSetLen_=$(MAX_MATCH_SET_LEN)" $(BUILD_ARGS)

.PHONY: clean-ebpf clean-ebpf-test ebpf ebpf-sync ebpf-sync-check ebpf-test-tagged ebpf-test-debug ebpf-test-debug-tagged ebpf-audit dae submodule submodules print-goexperiment print-goexperiment-env print-trace-unsupported

## Begin Dae Build
dae: export GOOS=linux
ifndef CGO_ENABLED
dae: export CGO_ENABLED=0
endif
dae: ebpf
	@echo $(CFLAGS)
	go build -tags=$(shell cat $(BUILD_TAGS_FILE)) -o $(OUTPUT) $(BUILD_ARGS) .
## End Dae Build

## Begin Git Submodules
.gitmodules.d.mk: .gitmodules
	@set -e && \
	submodules=$$(grep '\[submodule "' .gitmodules | cut -d'"' -f2 | tr '\n' ' ' | tr ' \n' '\n') && \
	echo "submodule_paths=$${submodules}" > $@

-include .gitmodules.d.mk

$(submodule_paths): .gitmodules.d.mk
	git submodule update --init --recursive -- $@ && \
	touch $@

submodule submodules: $(submodule_paths)
	@if [ -z "$(submodule_paths)" ]; then \
		rm -f .gitmodules.d.mk; \
		echo "Failed to generate submodules list. Please try again."; \
		exit 1; \
	fi
## End Git Submodules

## Begin Ebpf
clean-ebpf:
	@rm -f control/bpf_bpf*.go && \
			rm -f control/bpf_bpf*.o
	@rm -f control/bpftest_bpf*.go && \
			rm -f control/bpftest_bpf*.o
	@rm -f trace/bpf_*_bpf*.go && \
			rm -f trace/bpf_*_bpf*.o
	@rm -f control/kern/tests/bpftest_bpf*.go && \
			rm -f control/kern/tests/bpftest_bpf*.o
## clean-ebpf-test removes only what the eBPF test targets regenerate: the
## bpftest variants. Depending on clean-ebpf deleted the production objects as
## well, so after `make ebpf-test` the tree no longer built ("undefined:
## bpfObjects") until `make ebpf` ran again, even though the test targets never
## regenerate those files.
clean-ebpf-test:
	@rm -f control/bpftest_bpf*.go && \
			rm -f control/bpftest_bpf*.o
	@rm -f control/kern/tests/bpftest_bpf*.go && \
			rm -f control/kern/tests/bpftest_bpf*.o
fmt:
	go fmt ./...

ebpf-sync:
	@unset GOOS && \
	unset GOARCH && \
	unset GOARM && \
	unset GOAMD64 && \
	go generate ./common/consts/ebpf.go

ebpf-sync-check: ebpf-sync
	git diff --exit-code -- common/consts/ebpf_generated.go control/kern/ebpf_sync_defs.h

# $BPF_CLANG is used in go:generate invocations.
ebpf: export BPF_CLANG := $(CLANG)
ebpf: export BPF_STRIP_FLAG := $(STRIP_FLAG)
ebpf: export BPF_CFLAGS := $(CFLAGS)
ebpf: export BPF_TARGET := $(TARGET)
ebpf: export BPF_TRACE_TARGET := $(GOARCH)
ebpf: ebpf-sync submodule clean-ebpf
	@unset GOOS && \
    unset GOARCH && \
    unset GOARM && \
    echo $(STRIP_FLAG) && \
    go generate ./control/control.go && \
    if go generate ./trace/trace.go; then \
		echo trace > $(BUILD_TAGS_FILE); \
	elif [ -n "$(TRACE_UNSUPPORTED_THIS_ARCH)" ]; then \
		echo "WARNING: GOARCH=$(GOARCH) is declared in TRACE_UNSUPPORTED_GOARCH ($(TRACE_UNSUPPORTED_GOARCH)); building without the 'trace' tag, so 'dae trace' is unavailable in this binary." >&2; \
		echo > $(BUILD_TAGS_FILE); \
	else \
		echo "ERROR: trace eBPF generation failed for GOARCH=$(GOARCH), which is not declared in TRACE_UNSUPPORTED_GOARCH ($(TRACE_UNSUPPORTED_GOARCH)). Refusing to silently drop the 'trace' build tag; add $(GOARCH) to TRACE_UNSUPPORTED_GOARCH only after confirming the trace program cannot be generated for it." >&2; \
		exit 1; \
	fi

# Read-only accessors. These are the single source of truth that CI and the
# artifact assertions read instead of parsing/copying Makefile values.
print-goexperiment:
	@echo $(GOEXPERIMENT_MERGED)

# Same value in the `NAME=value` form consumed by $GITHUB_ENV, so a job that
# does not run `make` (a plain `go test`) can still build with the canonical
# experiment set without restating it. scripts/check-build-env.sh rejects a
# literal assignment under .github/, which is what keeps this the only owner.
print-goexperiment-env:
	@printf '%s=%s\n' GOEXPERIMENT "$(GOEXPERIMENT_MERGED)"

print-trace-unsupported:
	@echo $(TRACE_UNSUPPORTED_GOARCH)

EBPF_LINT_SOURCES := control/kern/tproxy.c control/kern/tests/bpf_test.c trace/kern/trace.c
EBPF_LINT_IGNORE := COMMIT_COMMENT_SYMBOL,NOT_UNIFIED_DIFF,COMMIT_LOG_LONG_LINE,LONG_LINE_COMMENT,VOLATILE,ASSIGN_IN_IF,PREFER_DEFINED_ATTRIBUTE_MACRO,CAMELCASE,LEADING_SPACE,OPEN_ENDED_LINE,SPACING,BLOCK_COMMENT_STYLE

ebpf-lint:
	./scripts/checkpatch.pl --no-tree --strict --no-summary --show-types --color=always $(EBPF_LINT_SOURCES) --ignore $(EBPF_LINT_IGNORE)

ebpf-test: export BPF_CLANG := $(CLANG)
ebpf-test: export BPF_STRIP_FLAG := $(STRIP_FLAG)
ebpf-test: export BPF_CFLAGS := $(CFLAGS)
ebpf-test: export BPF_TARGET := $(TARGET)
ebpf-test: export BPF_TRACE_TARGET := $(GOARCH)
ebpf-test: ebpf-sync submodule clean-ebpf-test
	@unset GOOS && \
    unset GOARCH && \
    unset GOARM && \
    echo $(STRIP_FLAG) && \
    go generate ./control/bpf_bug_verification_test.go && \
    go generate ./control/kern/tests/bpf_test.go && \
    go clean -testcache && \
    go test -v -tags dae_bpf_tests ./control/kern/tests/...

ebpf-test-tagged: export BPF_CLANG := $(CLANG)
ebpf-test-tagged: export BPF_STRIP_FLAG := $(STRIP_FLAG)
ebpf-test-tagged: export BPF_CFLAGS := $(CFLAGS)
ebpf-test-tagged: export BPF_TARGET := $(TARGET)
ebpf-test-tagged: export BPF_TRACE_TARGET := $(GOARCH)
ebpf-test-tagged: ebpf-sync submodule clean-ebpf-test
	@unset GOOS && \
    unset GOARCH && \
    unset GOARM && \
    echo $(STRIP_FLAG) && \
    go generate ./control/bpf_bug_verification_test.go && \
    go generate ./control/kern/tests/bpf_test.go && \
    go clean -testcache && \
    go test -v -tags dae_bpf_tests ./control/kern/tests/...

ebpf-test-debug: export BPF_CLANG := $(CLANG)
ebpf-test-debug: export BPF_STRIP_FLAG := $(STRIP_FLAG)
ebpf-test-debug: export BPF_CFLAGS := $(CFLAGS) -D__BPF_TEST_ENABLE_DEBUG
ebpf-test-debug: export BPF_TARGET := $(TARGET)
ebpf-test-debug: export BPF_TRACE_TARGET := $(GOARCH)
ebpf-test-debug: ebpf-sync submodule clean-ebpf-test
	@unset GOOS && \
    unset GOARCH && \
    unset GOARM && \
    echo $(STRIP_FLAG) && \
    go generate ./control/bpf_bug_verification_test.go && \
    go generate ./control/kern/tests/bpf_test.go && \
    go clean -testcache && \
    go test -v -tags dae_bpf_tests ./control/kern/tests/...

ebpf-test-debug-tagged: export BPF_CLANG := $(CLANG)
ebpf-test-debug-tagged: export BPF_STRIP_FLAG := $(STRIP_FLAG)
ebpf-test-debug-tagged: export BPF_CFLAGS := $(CFLAGS) -D__BPF_TEST_ENABLE_DEBUG
ebpf-test-debug-tagged: export BPF_TARGET := $(TARGET)
ebpf-test-debug-tagged: export BPF_TRACE_TARGET := $(GOARCH)
ebpf-test-debug-tagged: ebpf-sync submodule clean-ebpf-test
	@unset GOOS && \
    unset GOARCH && \
    unset GOARM && \
    echo $(STRIP_FLAG) && \
    go generate ./control/bpf_bug_verification_test.go && \
    go generate ./control/kern/tests/bpf_test.go && \
    go clean -testcache && \
    go test -v -tags dae_bpf_tests ./control/kern/tests/...

ebpf-audit:
	./scripts/ebpf-audit.sh

## End Ebpf
