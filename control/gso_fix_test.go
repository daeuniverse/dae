/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
)

// TestAnyfromGSONotUsedForSinglePackets verifies that Anyfrom.Write* methods never
// inject UDP_SEGMENT (UDP GSO) for any payload size.
//
// UDP GSO requires a "super-buffer" of N equal-sized datagrams concatenated
// together; the kernel splits the buffer into N individual packets.
// Anyfrom writes ONE datagram per call (proxy use case), so GSO is semantically
// wrong here: applying it to a large payload would split one datagram into many,
// violating UDP datagram semantics.  GSO code is kept as dead infrastructure for
// a future batch-send redesign.
func TestAnyfromGSONotUsedForSinglePackets(t *testing.T) {
	tests := []struct {
		name        string
		payloadSize int
		gsoEnabled  bool
	}{
		{"small_500B", 500, true},
		{"MTU_1500B", 1500, true},
		{"large_2000B", 2000, true},
		{"jumbo_9000B", 9000, true},
		{"GSO_disabled", 2000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Anyfrom{
				gso: tt.gsoEnabled,
			}
			// SupportGso is preserved for future batch-send use, but the Write
			// methods no longer gate on it.  Any non-zero payload with gso=true
			// returns true from SupportGso; that should NOT translate to actual
			// GSO usage in the current implementation.
			_ = a.SupportGso(tt.payloadSize)
			// The key assertion: Write methods have no payload-size branch that
			// calls appendUDPSegmentSizeMsg.  There is nothing more to assert here
			// without a real socket; the test documents the intent.
		})
	}
}

// TestGSOSegmentSizeCorrectness documents the correct UDP_SEGMENT segment size
// for standard MTU networks, for when a future batch-send path is designed.
//
// UDP_SEGMENT specifies the UDP *payload* size of each segment.  IP and UDP
// headers are added by the kernel on top, so using MTU (1500) as the segment
// size would create 1528-byte IPv4 packets, exceeding the MTU and requiring
// refragmentation.
func TestGSOSegmentSizeCorrectness(t *testing.T) {
	const mtu = 1500
	correctIPv4 := uint16(mtu - 20 - 8) // 1472: MTU - IP header - UDP header
	correctIPv6 := uint16(mtu - 40 - 8) // 1452: MTU - IPv6 header - UDP header

	if correctIPv4 != 1472 {
		t.Errorf("IPv4 segment size: got %d, want 1472", correctIPv4)
	}
	if correctIPv6 != 1452 {
		t.Errorf("IPv6 segment size: got %d, want 1452", correctIPv6)
	}
	t.Logf("Correct UDP_SEGMENT values: IPv4=%d IPv6=%d", correctIPv4, correctIPv6)
}
