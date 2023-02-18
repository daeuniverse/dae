/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package control

// $BPF_CLANG, $BPF_STRIP, $BPF_CFLAGS, $BPF_TARGET are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -strip $BPF_STRIP -cflags $BPF_CFLAGS -target $BPF_TARGET bpf kern/tproxy.c -- -I./headers

// Separate bpfObjectsLan and bpfObjectsWan from bpfObjects.
//go:generate go clean -cache
//go:generate go run github.com/v2rayA/dae/cmd/internal/generate_bpf_objects -o bpf_objects_wan_lan.go
//go:generate go fmt bpf_objects_wan_lan.go
