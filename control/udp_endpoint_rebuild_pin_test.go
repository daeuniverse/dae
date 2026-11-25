/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"net/netip"
	"testing"
	"time"

	daeerrors "github.com/daeuniverse/dae/common/errors"
	"golang.org/x/sys/unix"
)

func newStaleTrackedEndpoint(manager *SessionManager, src, dst netip.AddrPort) *UdpEndpoint {
	ue := &UdpEndpoint{conn: &mockPacketConn{}, udpConnStateOwner: manager}
	ue.TrackUdpConnStateTuplePair(src, dst)
	ue.hasReply.Store(true)
	stale := time.Now().Add(-2 * udpEndpointSendStaleTimeout).UnixNano()
	ue.lastSendNano.Store(stale)
	ue.lastReplyNano.Store(stale)
	return ue
}

// Regression for #1137: retiring a stale endpoint must keep the flow's
// conn-state until the replacement endpoint retains it.
func TestUdpEndpointStaleRebuildPinsConnStateUntilReplacementTracks(t *testing.T) {
	manager := NewSessionManager(context.Background())
	src := netip.MustParseAddrPort("192.0.2.51:3074")
	dst := netip.MustParseAddrPort("198.51.100.51:3074")
	keys := []bpfTuplesKey{
		bpfTuplesKeyFromAddrPorts(src, dst, uint8(unix.IPPROTO_UDP)),
		bpfTuplesKeyFromAddrPorts(dst, src, uint8(unix.IPPROTO_UDP)),
	}

	stale := newStaleTrackedEndpoint(manager, src, dst)
	_, err := stale.WriteTo([]byte("round two"), dst.String())
	if !stderrors.Is(err, daeerrors.ErrClosedConnection) {
		t.Fatalf("expected ErrClosedConnection on stale session, got: %v", err)
	}
	if !stale.dead.Load() {
		t.Fatal("stale endpoint must be retired")
	}
	pin := takeUdpEndpointRebuildPin(err)
	if pin == nil {
		t.Fatal("stale rebuild must hand over a conn-state pin")
	}
	if again := takeUdpEndpointRebuildPin(err); again != nil {
		t.Fatal("the pin must be handed out only once")
	}
	for _, key := range keys {
		if got := pinnedUDPRefs(manager, key); got != 1 {
			t.Fatalf("refs for %+v after retirement = %d, want 1 (the rebuild pin)", key, got)
		}
	}

	replacement := &UdpEndpoint{conn: &mockPacketConn{}, udpConnStateOwner: manager}
	replacement.TrackUdpConnStateTuplePair(src, dst)
	pin()
	for _, key := range keys {
		if got := pinnedUDPRefs(manager, key); got != 1 {
			t.Fatalf("refs for %+v after handover = %d, want 1 (the replacement)", key, got)
		}
	}

	replacement.releaseTrackedUdpConnState()
	for _, key := range keys {
		if got := pinnedUDPRefs(manager, key); got != 0 {
			t.Fatalf("refs for %+v after replacement release = %d, want 0", key, got)
		}
	}
}

// Without a replacement, unpinning releases the tuples as before.
func TestUdpEndpointStaleRebuildPinReleasesWithoutReplacement(t *testing.T) {
	manager := NewSessionManager(context.Background())
	src := netip.MustParseAddrPort("192.0.2.52:3074")
	dst := netip.MustParseAddrPort("198.51.100.52:3074")

	stale := newStaleTrackedEndpoint(manager, src, dst)
	_, err := stale.WriteTo([]byte("round two"), dst.String())
	pin := takeUdpEndpointRebuildPin(err)
	if pin == nil {
		t.Fatalf("stale rebuild must hand over a conn-state pin, err=%v", err)
	}
	pin()
	for _, key := range []bpfTuplesKey{
		bpfTuplesKeyFromAddrPorts(src, dst, uint8(unix.IPPROTO_UDP)),
		bpfTuplesKeyFromAddrPorts(dst, src, uint8(unix.IPPROTO_UDP)),
	} {
		if got := pinnedUDPRefs(manager, key); got != 0 {
			t.Fatalf("refs for %+v = %d, want 0", key, got)
		}
	}
}

func TestChainUdpConnStatePins(t *testing.T) {
	if chainUdpConnStatePins(nil, nil) != nil {
		t.Fatal("two nil pins must chain to nil")
	}
	var order []int
	first := func() { order = append(order, 1) }
	second := func() { order = append(order, 2) }
	chainUdpConnStatePins(first, nil)()
	chainUdpConnStatePins(nil, second)()
	chainUdpConnStatePins(first, second)()
	want := []int{1, 2, 2, 1}
	if len(order) != len(want) {
		t.Fatalf("release order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("release order = %v, want %v", order, want)
		}
	}
}
