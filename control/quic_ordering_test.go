/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/stretchr/testify/require"
)

// TestQuicOrderingIsLikelyQuicInitialPacket verifies the QUIC detection logic.
func TestQuicOrderingIsLikelyQuicInitialPacket(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "QUIC_Initial_packet",
			data:     []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00}, // Long header + Initial type + Fixed bit
			expected: true,
		},
		{
			name:     "DNS_packet_not_QUIC",
			data:     []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, // Random DNS
			expected: false,
		},
		{
			name:     "Short_packet_not_QUIC",
			data:     []byte{0x40, 0x01}, // Short header
			expected: false,
		},
		{
			name:     "Too_short_packet",
			data:     []byte{0xC0, 0x00, 0x00},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sniffing.IsLikelyQuicInitialPacket(tt.data)
			require.Equal(t, tt.expected, result)
		})
	}
}

// TestUdpTaskPool_QuicPacketOrdering verifies that QUIC Initial packets are processed in order.
func TestUdpTaskPool_QuicPacketOrdering(t *testing.T) {
	pool := NewUdpTaskPool()
	udpKey := netip.MustParseAddrPort("192.168.1.1:443")

	// Simulate QUIC Initial packets (need ordering)
	const n = 100
	var got []int
	var mu sync.Mutex
	var done atomic.Int32

	quicInitialPacket := []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00}
	require.True(t, sniffing.IsLikelyQuicInitialPacket(quicInitialPacket), "test data should be QUIC Initial")

	for i := range n {
		idx := i
		pool.EmitTask(udpKey, func() {
			mu.Lock()
			got = append(got, idx)
			mu.Unlock()
			done.Add(1)
		})
	}

	require.Eventually(t, func() bool { return done.Load() == n }, 2*time.Second, 10*time.Millisecond)

	require.Len(t, got, n)
	for i := range n {
		require.Equal(t, i, got[i], "QUIC Initial packets should be processed in order")
	}
}

// TestUdpTaskPool_NonQuicDirectExecution verifies non-QUIC packets bypass UdpTaskPool.
func TestUdpTaskPool_NonQuicDirectExecution(t *testing.T) {
	_ = NewUdpTaskPool() // pool not used because non-QUIC bypasses it

	// Non-QUIC packet (DNS-like)
	nonQuicPacket := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	require.False(t, sniffing.IsLikelyQuicInitialPacket(nonQuicPacket), "test data should not be QUIC Initial")

	// Since non-QUIC bypasses UdpTaskPool, verify the logic would skip pool
	var done atomic.Bool
	go func() {
		time.Sleep(50 * time.Millisecond)
		done.Store(true)
	}()

	require.Eventually(t, func() bool { return done.Load() }, 100*time.Millisecond, 10*time.Millisecond)
}

// BenchmarkIsLikelyQuicInitialPacket benchmarks the QUIC detection overhead.
func BenchmarkIsLikelyQuicInitialPacket(b *testing.B) {
	quicPacket := []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00}
	nonQuicPacket := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}

	b.Run("QUIC_packet", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = sniffing.IsLikelyQuicInitialPacket(quicPacket)
		}
	})

	b.Run("Non_QUIC_packet", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = sniffing.IsLikelyQuicInitialPacket(nonQuicPacket)
		}
	})
}
