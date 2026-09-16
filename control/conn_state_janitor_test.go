//go:build linux && !dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"io"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// Boundary test for the conn_state janitor: exercise the real scan/delete path
// against a real kernel map and check exactly which entries survive. The
// thresholds are read from the production constants so the test fails if a
// timeout or a branch changes meaning.
func TestConnStateJanitorBoundaries(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "conn_state_map",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(bpfTuplesKey{})),
		ValueSize:  uint32(unsafe.Sizeof(bpfConnState{})),
		MaxEntries: 64,
	})
	if err != nil {
		t.Skipf("cannot create conn_state_map: %v", err)
	}
	defer func() { _ = m.Close() }()

	cp := &ControlPlane{}
	log := logrus.New()
	log.SetOutput(io.Discard)
	cp.log = log
	cp.core = &controlPlaneCore{}
	cp.core.InjectBpf(&bpfObjects{bpfMaps: bpfMaps{ConnStateMap: m}})
	cp.stop = make(chan struct{})

	// The janitor reads CLOCK_MONOTONIC, so the fabricated ages must share that
	// time base; wall-clock timestamps would make every age negative.
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatalf("CLOCK_MONOTONIC: %v", err)
	}
	now := ts.Nano()
	dnsPort := uint16(53)
	if binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&dnsPort))[:]) == 53 {
		dnsPort = binary.BigEndian.Uint16([]byte{0, 53})
	} else {
		dnsPort = binary.BigEndian.Uint16([]byte{53, 0})
	}

	udpKey := func(sport, dport uint16, last byte) bpfTuplesKey {
		var k bpfTuplesKey
		k.Sport, k.Dport, k.L4proto = sport, dport, unix.IPPROTO_UDP
		k.Sip.U6Addr8[15] = last
		k.Dip.U6Addr8[15] = 0x63
		return k
	}
	tcpKey := func(sport, dport uint16, last byte) bpfTuplesKey {
		var k bpfTuplesKey
		k.Sport, k.Dport, k.L4proto = sport, dport, unix.IPPROTO_TCP
		k.Sip.U6Addr8[15] = last
		k.Dip.U6Addr8[15] = 0x63
		return k
	}
	state := func(lastSeenNs uint64, st uint8, hasRouting uint8) bpfConnState {
		var v bpfConnState
		v.LastSeenNs = lastSeenNs
		v.State = st
		v.Meta.Data.HasRouting = hasRouting
		return v
	}

	normalTimeout := QuicNatTimeout.Nanoseconds()
	dnsTimeout := udpConnStateTimeoutDNS.Nanoseconds()
	closingTimeout := tcpConnStateTimeoutClosing.Nanoseconds()
	routinglessBackstop := tcpConnStateRoutinglessBackstop.Nanoseconds()
	sec := time.Second.Nanoseconds()

	type entry struct {
		name  string
		key   bpfTuplesKey
		value bpfConnState
		want  bool // true = must survive
	}
	entries := []entry{
		{"udp fresh", udpKey(1001, 443, 1), state(uint64(now-normalTimeout/2), 0, 1), true},
		{"udp expired", udpKey(1002, 443, 2), state(uint64(now-normalTimeout-sec), 0, 1), false},
		{"udp dns fresh", udpKey(1003, dnsPort, 3), state(uint64(now-dnsTimeout/2), 0, 1), true},
		{"udp dns expired", udpKey(1004, dnsPort, 4), state(uint64(now-dnsTimeout-sec), 0, 1), false},
		{"tcp established with routing", tcpKey(2001, 443, 5), state(uint64(now-sec), 0, 1), true},
		{"tcp closing fresh", tcpKey(2002, 443, 6), state(uint64(now-closingTimeout/2), 1, 1), true},
		{"tcp closing expired", tcpKey(2003, 443, 7), state(uint64(now-closingTimeout-sec), 1, 1), false},
		{"tcp routingless fresh", tcpKey(2004, 443, 8), state(uint64(now-sec), 0, 0), true},
		{"tcp routingless expired", tcpKey(2005, 443, 9), state(uint64(now-routinglessBackstop-sec), 0, 0), false},
		{"tcp zero last-seen", tcpKey(2006, 443, 10), state(0, 0, 1), true},
	}
	for _, e := range entries {
		if err := m.Put(e.key, e.value); err != nil {
			t.Fatalf("put %s: %v", e.name, err)
		}
	}

	udpStats, tcpStats := cp.cleanupConnStateMapBeforeLocked(false, 0)
	t.Logf("janitor stats: udp=%+v tcp=%+v", udpStats, tcpStats)

	for _, e := range entries {
		var got bpfConnState
		err := m.Lookup(e.key, &got)
		exists := err == nil
		if exists != e.want {
			t.Errorf("%s: entry %s, want %s", e.name, map[bool]string{true: "survived", false: "deleted"}[exists], map[bool]string{true: "survived", false: "deleted"}[e.want])
		}
	}

	// The staleBeforeNs backstop must retire everything older than the marker,
	// including entries the age thresholds would keep.
	staleBefore := uint64(now - sec)
	staleKey := udpKey(3001, 443, 11)
	// Last seen before the marker but well inside the TTL: the stale-marker path
	// is the only reason this entry may be retired.
	if err := m.Put(staleKey, state(uint64(now-2*sec), 0, 1)); err != nil {
		t.Fatalf("put stale-marker entry: %v", err)
	}
	cp.cleanupConnStateMapBeforeLocked(false, staleBefore)
	if err := m.Lookup(staleKey, &bpfConnState{}); err == nil {
		t.Error("entry younger than the TTL but older than staleBeforeNs must be retired")
	}

	// A stopped control plane must not touch the map at all.
	stopKey := udpKey(3002, 443, 12)
	if err := m.Put(stopKey, state(uint64(now-10*normalTimeout), 0, 1)); err != nil {
		t.Fatalf("put stop-path entry: %v", err)
	}
	close(cp.stop)
	cp.cleanupConnStateMapBeforeLocked(false, 0)
	if err := m.Lookup(stopKey, &bpfConnState{}); err != nil {
		t.Errorf("janitor must not modify the map after stop: %v", err)
	}
}
