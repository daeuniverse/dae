/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, v2rayA Organization <team@v2raya.org>
 */

package control

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate sh -c "bpftool btf dump file /sys/kernel/btf/vmlinux format c > kern/headers/vmlinux.h"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -strip $BPF_STRIP -cflags $BPF_CFLAGS -target $BPF_TARGET bpf kern/tproxy.c -- -I./headers
