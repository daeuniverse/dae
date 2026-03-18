/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"sync/atomic"
	"testing"
)

// TestUdpFlowDispatchStrategy tests the dispatch strategy classification.
func TestUdpFlowDispatchStrategy(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		dst      string
		data     []byte
		expected UdpDispatchStrategy
	}{
		// DNS - Direct Goroutine
		{"DNS query", "192.168.1.1:12345", "8.8.8.8:53", nil, StrategyDirectGoroutine},
		{"DNS response", "8.8.8.8:53", "192.168.1.1:12345", nil, StrategyDirectGoroutine},
		{"DNS over IPv6", "[::1]:12345", "[2001:db8::1]:53", nil, StrategyDirectGoroutine},

		// VoIP - Direct Goroutine
		{"SIP signaling", "192.168.1.1:12345", "1.1.1.1:5060", nil, StrategyDirectGoroutine},
		{"RTP media", "192.168.1.1:12345", "1.1.1.1:5004", nil, StrategyDirectGoroutine},
		{"RTP port range", "192.168.1.1:12345", "1.1.1.1:5060", nil, StrategyDirectGoroutine},

		// STUN - Direct Goroutine
		{"STUN", "192.168.1.1:12345", "1.1.1.1:3478", nil, StrategyDirectGoroutine},

		// WireGuard - Bounded Pool
		{"WireGuard", "192.168.1.1:12345", "1.1.1.1:51820", nil, StrategyBoundedPool},

		// OpenVPN - Bounded Pool
		{"OpenVPN", "192.168.1.1:12345", "1.1.1.1:1194", nil, StrategyBoundedPool},

		// IPsec IKE - Bounded Pool
		{"IPsec IKE", "192.168.1.1:12345", "1.1.1.1:500", nil, StrategyBoundedPool},

		// QUIC Initial - Ordered Ingress (using actual QUIC Initial packet data)
		{"QUIC Initial", "192.168.1.1:12345", "1.1.1.1:443", []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00}, StrategyOrderedIngress},

		// QUIC data (after initial) - Bounded Pool
		{"QUIC data", "192.168.1.1:12345", "1.1.1.1:443", nil, StrategyBoundedPool},

		// Generic UDP - Direct Goroutine (default safe option)
		{"Generic UDP", "192.168.1.1:12345", "1.1.1.1:8080", nil, StrategyDirectGoroutine},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := mustParseAddrPort(tt.src)
			dst := mustParseAddrPort(tt.dst)
			decision := ClassifyUdpFlow(src, dst, tt.data)
			got := decision.DispatchStrategy()

			if got != tt.expected {
				t.Errorf("DispatchStrategy() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestUdpFlowShouldUseGoroutineDirectly tests direct goroutine classification.
func TestUdpFlowShouldUseGoroutineDirectly(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		dst      string
		expected bool
	}{
		{"DNS query", "192.168.1.1:12345", "8.8.8.8:53", true},
		{"DNS response", "8.8.8.8:53", "192.168.1.1:12345", true},
		{"SIP", "192.168.1.1:12345", "1.1.1.1:5060", true},
		{"RTP", "192.168.1.1:12345", "1.1.1.1:5004", true},
		{"STUN", "192.168.1.1:12345", "1.1.1.1:3478", true},
		{"WireGuard", "192.168.1.1:12345", "1.1.1.1:51820", false},
		{"HTTPS", "192.168.1.1:12345", "1.1.1.1:443", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := mustParseAddrPort(tt.src)
			dst := mustParseAddrPort(tt.dst)
			decision := ClassifyUdpFlow(src, dst, nil)

			if got := decision.ShouldUseGoroutineDirectly(); got != tt.expected {
				t.Errorf("ShouldUseGoroutineDirectly() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestUdpFlowShouldUseBoundedPool tests bounded pool classification.
func TestUdpFlowShouldUseBoundedPool(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		dst      string
		isQuic   bool
		expected bool
	}{
		{"WireGuard", "192.168.1.1:12345", "1.1.1.1:51820", false, true},
		{"OpenVPN", "192.168.1.1:12345", "1.1.1.1:1194", false, true},
		{"IPsec IKE", "192.168.1.1:12345", "1.1.1.1:500", false, true},
		{"QUIC data", "192.168.1.1:12345", "1.1.1.1:443", false, true},
		{"DNS", "192.168.1.1:12345", "8.8.8.8:53", false, false},
		{"SIP", "192.168.1.1:12345", "1.1.1.1:5060", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := mustParseAddrPort(tt.src)
			dst := mustParseAddrPort(tt.dst)
			decision := ClassifyUdpFlow(src, dst, nil)

			if got := decision.ShouldUseBoundedPool(); got != tt.expected {
				t.Errorf("ShouldUseBoundedPool() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestBoundedPoolBasic tests the bounded pool functionality.
func TestBoundedPoolBasic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := NewBoundedGoroutinePool(ctx, 10)
	defer pool.Close()

	var completed atomic.Int64

	// Submit 5 tasks - all should succeed
	for i := 0; i < 5; i++ {
		if !pool.Submit(func() {
			completed.Add(1)
		}) {
			t.Errorf("Submit should succeed when pool is not full")
		}
	}

	pool.Close()
	if completed.Load() != 5 {
		t.Errorf("Expected 5 completed tasks, got %d", completed.Load())
	}
}

// BenchmarkUdpFlowClassification benchmarks the flow classification.
func BenchmarkUdpFlowClassification(b *testing.B) {
	src := mustParseAddrPort("192.168.1.1:12345")
	dst := mustParseAddrPort("8.8.8.8:1:53")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decision := ClassifyUdpFlow(src, dst, nil)
		_ = decision.DispatchStrategy()
	}
}
