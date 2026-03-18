/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestDispatchPattern_NoDropForDNS verifies that DNS traffic doesn't get dropped.
func TestDispatchPattern_NoDropForDNS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	runner := newUdpUnorderedTaskRunner(ctx, 2, 32) // Small queue to test drops

	dnsSrc := mustParseAddrPort("192.168.1.1:12345")
	dnsDst := mustParseAddrPort("8.8.8.8:53")
	dnsKey := NewUdpFlowKey(dnsSrc, dnsDst)

	nonDnsSrc := mustParseAddrPort("192.168.1.1:54321")
	nonDnsDst := mustParseAddrPort("1.1.1.1:80")
	nonDnsKey := NewUdpFlowKey(nonDnsSrc, nonDnsDst)

	var dnsSubmitted atomic.Int64
	var dnsDropped atomic.Int64
	var dnsCompleted atomic.Int64

	var nonDnsSubmitted atomic.Int64
	var nonDnsDropped atomic.Int64
	var nonDnsCompleted atomic.Int64

	// Simulate high load - flood the queue with non-DNS traffic first
	for i := 0; i < 1000; i++ {
		task := func() {
			time.Sleep(100 * time.Millisecond)
			nonDnsCompleted.Add(1)
		}
		nonDnsSubmitted.Add(1)
		if !runner.Submit(nonDnsKey, task) {
			nonDnsDropped.Add(1)
		}
	}

	// Now try to submit DNS traffic
	for i := 0; i < 100; i++ {
		task := func() {
			time.Sleep(10 * time.Millisecond)
			dnsCompleted.Add(1)
		}
		dnsSubmitted.Add(1)
		// DNS traffic should use direct goroutine, not the queue
		flowDecision := UdpFlowDecision{
			Key: dnsKey,
		}
		if flowDecision.ShouldUseGoroutineDirectly() {
			// Direct spawn - no drop possible
			go task()
		} else {
			if !runner.Submit(dnsKey, task) {
				dnsDropped.Add(1)
			}
		}
	}

	// Wait a bit for tasks to complete
	time.Sleep(200 * time.Millisecond)

	// Verify DNS traffic wasn't dropped
	dnsDropRate := float64(dnsDropped.Load()) / float64(dnsSubmitted.Load())
	t.Logf("DNS: Submitted=%d, Dropped=%d, Completed=%d, DropRate=%.2f%%",
		dnsSubmitted.Load(), dnsDropped.Load(), dnsCompleted.Load(), dnsDropRate*100)

	if dnsDropped.Load() > 0 {
		t.Errorf("DNS traffic should never be dropped, but got %d drops", dnsDropped.Load())
	}

	// Non-DNS traffic likely had drops (queue is small)
	nonDnsDropRate := float64(nonDnsDropped.Load()) / float64(nonDnsSubmitted.Load())
	t.Logf("Non-DNS: Submitted=%d, Dropped=%d, Completed=%d, DropRate=%.2f%%",
		nonDnsSubmitted.Load(), nonDnsDropped.Load(), nonDnsCompleted.Load(), nonDnsDropRate*100)
}

// TestUdpFlowDecision_ShouldUseGoroutineDirectly tests the classification logic.
func TestUdpFlowDecision_ShouldUseGoroutineDirectly(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		dst      string
		expected bool
	}{
		{"DNS query (port 53)", "192.168.1.1:12345", "8.8.8.8:53", true},
		{"DNS response (port 53)", "8.8.8.8:53", "192.168.1.1:12345", true},
		{"DNS over IPv6", "[::1]:12345", "[2001:db8::1]:53", true},
		{"HTTPS (443)", "192.168.1.1:12345", "1.1.1.1:443", false},
		{"HTTP (80)", "192.168.1.1:12345", "1.1.1.1:80", false},
		{"WireGuard (51820)", "192.168.1.1:12345", "1.1.1.1:51820", false},
		{"QUIC (443)", "192.168.1.1:12345", "1.1.1.1:443", false},
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
