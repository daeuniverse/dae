//go:build trace && dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package trace

import (
	"errors"

	"github.com/cilium/ebpf"
)

var errBpfObjectsUnavailable = errors.New("eBPF objects are unavailable in this build; this is a stub build (tag dae_stub_ebpf); run make ebpf before building")

type bpfObjects struct {
	KprobeSkb1                   *ebpf.Program
	KprobeSkb2                   *ebpf.Program
	KprobeSkb3                   *ebpf.Program
	KprobeSkb4                   *ebpf.Program
	KprobeSkb5                   *ebpf.Program
	KprobeSkbLifetimeTermination *ebpf.Program
	Events                       *ebpf.Map
	TraceStats                   *ebpf.Map
}

func (o *bpfObjects) Close() error {
	return nil
}

func loadBpf() (*ebpf.CollectionSpec, error) {
	return nil, errBpfObjectsUnavailable
}
