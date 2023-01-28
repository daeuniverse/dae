#
#  SPDX-License-Identifier: AGPL-3.0-only
#  Copyright (c) since 2022, mzz2017 <mzz@tuta.io>
#

# The development version of clang is distributed as the 'clang' binary,
# while stable/released versions have a version number attached.
# Pin the default clang to a stable version.
CLANG ?= clang
STRIP ?= llvm-strip
CFLAGS := -O2 -Wall -Werror $(CFLAGS)

# Get version from .git.
date=$(shell git log -1 --format="%cd" --date=short | sed s/-//g)
count=$(shell git rev-list --count HEAD)
commit=$(shell git rev-parse --short HEAD)
ifeq ($(wildcard .git/.),)
	VERSION ?= unstable-0.nogit
else
	VERSION ?= unstable-$(date).r$(count).$(commit)
endif

.PHONY: ebpf dae

dae: ebpf
	go build -ldflags "-s -w -X github.com/v2rayA/dae/cmd.Version=$(VERSION)" .

# $BPF_CLANG is used in go:generate invocations.
ebpf: export BPF_CLANG := $(CLANG)
ebpf: export BPF_STRIP := $(STRIP)
ebpf: export BPF_CFLAGS := $(CFLAGS)
ebpf:
	go generate ./component/control/...
