/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package control

// $BPF_CLANG, $BPF_STRIP, $BPF_CFLAGS, $BPF_TARGET are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -strip $BPF_STRIP -cflags $BPF_CFLAGS -target $BPF_TARGET bpf kern/tproxy.c -- -I./headers

