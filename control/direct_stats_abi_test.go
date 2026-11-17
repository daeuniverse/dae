//go:build !dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/btf"
)

// TestDirectStatsConnStateABIParity pins the shared-map contract: the observer
// reads conn_state_map through a struct it declares itself, so a field added or
// reordered in tproxy.c without the same change here would make the observer
// read another field's bytes and silently report the wrong flow as direct.
func TestDirectStatsConnStateABIParity(t *testing.T) {
	if got, want := unsafe.Sizeof(directstatsConnState{}), unsafe.Sizeof(bpfConnState{}); got != want {
		t.Fatalf("direct_stats conn_state is %d bytes but tproxy's is %d", got, want)
	}
	type offset struct {
		name string
		got  uintptr
		want uintptr
	}
	for _, off := range []offset{
		{"LastSeenNs", unsafe.Offsetof(directstatsConnState{}.LastSeenNs), unsafe.Offsetof(bpfConnState{}.LastSeenNs)},
		{"Meta", unsafe.Offsetof(directstatsConnState{}.Meta), unsafe.Offsetof(bpfConnState{}.Meta)},
		{"Meta.Data.Mark", unsafe.Offsetof(directstatsConnState{}.Meta.Data.Mark), unsafe.Offsetof(bpfConnState{}.Meta.Data.Mark)},
		{"Meta.Data.Outbound", unsafe.Offsetof(directstatsConnState{}.Meta.Data.Outbound), unsafe.Offsetof(bpfConnState{}.Meta.Data.Outbound)},
		{"Meta.Data.Must", unsafe.Offsetof(directstatsConnState{}.Meta.Data.Must), unsafe.Offsetof(bpfConnState{}.Meta.Data.Must)},
		{"Meta.Data.Dscp", unsafe.Offsetof(directstatsConnState{}.Meta.Data.Dscp), unsafe.Offsetof(bpfConnState{}.Meta.Data.Dscp)},
		{"Meta.Data.HasRouting", unsafe.Offsetof(directstatsConnState{}.Meta.Data.HasRouting), unsafe.Offsetof(bpfConnState{}.Meta.Data.HasRouting)},
		{"Mac", unsafe.Offsetof(directstatsConnState{}.Mac), unsafe.Offsetof(bpfConnState{}.Mac)},
		{"Pname", unsafe.Offsetof(directstatsConnState{}.Pname), unsafe.Offsetof(bpfConnState{}.Pname)},
		{"Pid", unsafe.Offsetof(directstatsConnState{}.Pid), unsafe.Offsetof(bpfConnState{}.Pid)},
		{"DirectPassthrough", unsafe.Offsetof(directstatsConnState{}.DirectPassthrough), unsafe.Offsetof(bpfConnState{}.DirectPassthrough)},
		{"DatapathGeneration", unsafe.Offsetof(directstatsConnState{}.DatapathGeneration), unsafe.Offsetof(bpfConnState{}.DatapathGeneration)},
	} {
		if off.got != off.want {
			t.Errorf("conn_state field %s is at offset %d in the observer but %d in tproxy", off.name, off.got, off.want)
		}
	}
}

// TestDirectStatsTuplesKeyABIParity pins the map key layout the observer builds
// independently of tproxy.
func TestDirectStatsTuplesKeyABIParity(t *testing.T) {
	if got, want := unsafe.Sizeof(directstatsTuplesKey{}), unsafe.Sizeof(bpfTuplesKey{}); got != want {
		t.Fatalf("direct_stats tuples_key is %d bytes but tproxy's is %d", got, want)
	}
	for _, off := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"Sport", unsafe.Offsetof(directstatsTuplesKey{}.Sport), unsafe.Offsetof(bpfTuplesKey{}.Sport)},
		{"Dport", unsafe.Offsetof(directstatsTuplesKey{}.Dport), unsafe.Offsetof(bpfTuplesKey{}.Dport)},
		{"L4proto", unsafe.Offsetof(directstatsTuplesKey{}.L4proto), unsafe.Offsetof(bpfTuplesKey{}.L4proto)},
	} {
		if off.got != off.want {
			t.Errorf("tuples_key field %s is at offset %d in the observer but %d in tproxy", off.name, off.got, off.want)
		}
	}
}

// TestDirectStatsObjectHasNoNATReverseMap pins the generated object: the
// observer's only map besides tproxy's conn_state_map is the counter array.
// The source-level check lives in direct_stats_test.go; this one needs the
// real object and therefore lives in the !dae_stub_ebpf file.
func TestDirectStatsObjectHasNoNATReverseMap(t *testing.T) {
	spec, err := loadDirectstats()
	if err != nil {
		t.Fatalf("load observer spec: %v", err)
	}
	if spec.Maps["direct_reverse_map"] != nil {
		t.Fatal("generated observer still allocates the unsafe NAT reverse map")
	}
}

// TestDirectStatsCounterValueLayout pins the counter-map value the Go reader
// decodes. The map has one entry per direction; each entry is {bytes, packets}.
func TestDirectStatsCounterValueLayout(t *testing.T) {
	spec, err := loadDirectstats()
	if err != nil {
		t.Fatalf("load observer spec: %v", err)
	}
	value := spec.Maps["direct_stats_map"]
	if value == nil || value.Value == nil {
		t.Fatal("direct_stats_map has no value type")
	}
	size, err := btf.Sizeof(value.Value)
	if err != nil {
		t.Fatalf("size of direct_stats_map value: %v", err)
	}
	if got, want := uint32(size), uint32(unsafe.Sizeof(directStatsValue{})); got != want {
		t.Fatalf("direct_stats_map value size = %d, want %d", got, want)
	}
}
