/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/sirupsen/logrus"
)

// Locks the raw UDP fallback payload bound: the 16-bit UDP length field would
// wrap above 65507 bytes (65535 - 20 IPv4 header - 8 UDP header).
func TestValidateUDPRawPayloadLength(t *testing.T) {
	if err := validateUDPRawPayloadLength(0); err != nil {
		t.Fatalf("empty payload should pass: %v", err)
	}
	if err := validateUDPRawPayloadLength(maxUDPRawPayloadLength); err != nil {
		t.Fatalf("boundary payload should pass: %v", err)
	}
	if err := validateUDPRawPayloadLength(maxUDPRawPayloadLength + 1); err == nil {
		t.Fatal("oversized payload must be rejected (UDP length field would wrap)")
	}
}

// Locks ParsePortRange against a slice-out-of-bounds panic on short input.
func TestParsePortRangeShortInput(t *testing.T) {
	for n := range 4 {
		buf := make([]byte, n)
		start, end := ParsePortRange(buf) // must not panic
		if start != 0 || end != 0 {
			t.Fatalf("len=%d: expected (0,0), got (%d,%d)", n, start, end)
		}
	}
	encoded := (bpfPortRange{PortStart: 1, PortEnd: 0xFF}).Encode()
	start, end := ParsePortRange(encoded[:])
	if start != 1 || end != 0xFF {
		t.Fatalf("expected (1,255), got (%d,%d)", start, end)
	}
}

// Locks releaseQueueCh idempotence: Close and the exiting convoy goroutine
// race over the same channel; a double-put would let sync.Pool hand the same
// channel to two queues. sync.Pool does not guarantee that Get returns a
// previously Put object (and under -race/GC pressure it often does not), so
// this asserts the guard state machine instead of pool round-trip behavior.
// If the CAS guard is ever replaced with an unconditional Put, chReturned is
// never set and this test fails.
func TestReleaseQueueChIdempotent(t *testing.T) {
	p := NewUdpTaskPool()
	q := &UdpTaskQueue{p: p, ch: make(chan UdpTask)}

	p.releaseQueueCh(q)
	p.releaseQueueCh(q) // second call must be a no-op

	if !q.chReturned.Load() {
		t.Fatal("releaseQueueCh must set the returned guard via CAS")
	}
	if q.chReturned.CompareAndSwap(false, true) {
		t.Fatal("guard was already set; a second CAS must fail (double-put was possible)")
	}
}

// Locks the reply-drop telemetry: local reinjection failures are swallowed by
// design (endpoint survives), but must be countable.
func TestForwardUdpEndpointReplyToClientCountsDrops(t *testing.T) {
	before := udpReplyReinjectionDrops.Load()
	recorded := 0
	send := udpEndpointReplySender(func(log *logrus.Logger, data []byte, from netip.AddrPort, realTo netip.AddrPort, slot udpEndpointResponseConnSlot) error {
		return errors.New("reinjection failed")
	})
	err := forwardUdpEndpointReplyToClient(
		logrus.New(), nil, []byte("d"),
		netip.MustParseAddrPort("1.1.1.1:1"), netip.MustParseAddrPort("2.2.2.2:2"),
		send, func(n int64) { recorded += int(n) })
	if err != nil {
		t.Fatalf("reply drop must be swallowed, got %v", err)
	}
	if udpReplyReinjectionDrops.Load() != before+1 {
		t.Fatal("expected drop counter to increment exactly once")
	}
	if recorded != 0 {
		t.Fatalf("download must not be recorded for a dropped reply, got %d", recorded)
	}
}
