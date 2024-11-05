#
#  SPDX-License-Identifier: AGPL-3.0-only
#  Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
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

# Do NOT remove the line below. This line is for CI.
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

.PHONY: clean-ebpf ebpf dae submodule submodules

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
	@rm -f trace/bpf_bpf*.go && \
		rm -f trace/bpf_bpf*.o
	@rm -f control/kern/tests/bpftest_bpf*.go && \
		rm -f control/kern/tests/bpftest_bpf*.o
fmt:
	go fmt ./...

# $BPF_CLANG is used in go:generate invocations.
ebpf: export BPF_CLANG := $(CLANG)
ebpf: export BPF_STRIP_FLAG := $(STRIP_FLAG)
ebpf: export BPF_CFLAGS := $(CFLAGS)
ebpf: export BPF_TARGET := $(TARGET)
ebpf: export BPF_TRACE_TARGET := $(GOARCH)
ebpf: submodule clean-ebpf
	@unset GOOS && \
    unset GOARCH && \
    unset GOARM && \
    echo $(STRIP_FLAG) && \
    go generate ./control/control.go && \
    go generate ./trace/trace.go && echo trace > $(BUILD_TAGS_FILE) || echo > $(BUILD_TAGS_FILE)

ebpf-lint:
	./scripts/checkpatch.pl --no-tree --strict --no-summary --show-types --color=always control/kern/tproxy.c --ignore COMMIT_COMMENT_SYMBOL,NOT_UNIFIED_DIFF,COMMIT_LOG_LONG_LINE,LONG_LINE_COMMENT,VOLATILE,ASSIGN_IN_IF,PREFER_DEFINED_ATTRIBUTE_MACRO,CAMELCASE,LEADING_SPACE,OPEN_ENDED_LINE,SPACING,BLOCK_COMMENT_STYLE

ebpf-test: export BPF_CLANG := $(CLANG)
ebpf-test: export BPF_STRIP_FLAG := $(STRIP_FLAG)
ebpf-test: export BPF_CFLAGS := $(CFLAGS)
ebpf-test: export BPF_TARGET := $(TARGET)
ebpf-test: export BPF_TRACE_TARGET := $(GOARCH)
ebpf-test: submodule clean-ebpf
	@unset GOOS && \
    unset GOARCH && \
    unset GOARM && \
    echo $(STRIP_FLAG) && \
    go generate ./control/kern/tests/bpf_test.go && \
    go clean -testcache && \
    go test -v ./control/kern/tests/...

## End Ebpf
