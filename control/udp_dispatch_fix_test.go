/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"
	"sync"
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
		} else if !runner.Submit(dnsKey, task) {
			dnsDropped.Add(1)
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

func TestUdpFlowDecision_SessionTrafficUsesOrderedIngress(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		dst     string
		payload []byte
	}{
		{
			name:    "plain game udp on random port",
			src:     "192.168.1.10:40000",
			dst:     "203.0.113.10:27015",
			payload: []byte{0x01, 0x02, 0x03},
		},
		{
			name:    "wireguard keeps session fifo",
			src:     "192.168.1.10:40001",
			dst:     "203.0.113.20:51820",
			payload: []byte{0x11, 0x22, 0x33},
		},
		{
			name:    "quic-like payload on non-allowlisted port still uses ordered ingress",
			src:     "192.168.1.10:40002",
			dst:     "203.0.113.30:30000",
			payload: []byte{0xc3, 0x00, 0x00, 0x00, 0x01},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := mustParseAddrPort(tt.src)
			dst := mustParseAddrPort(tt.dst)
			decision := ClassifyUdpFlow(src, dst, tt.payload)

			if !decision.ShouldUseOrderedIngress() {
				t.Fatal("ShouldUseOrderedIngress() = false, want true")
			}
			if got := decision.DispatchStrategy(); got != StrategyOrderedIngress {
				t.Fatalf("DispatchStrategy() = %v, want %v", got, StrategyOrderedIngress)
			}
		})
	}
}

func TestUdpFlowDecision_QuicInitialUsesOrderedIngress(t *testing.T) {
	quicInitialPayload := []byte{0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00}
	src := mustParseAddrPort("192.168.1.10:40100")
	dst := mustParseAddrPort("203.0.113.40:443")

	decision := ClassifyUdpFlow(src, dst, quicInitialPayload)
	if !decision.ShouldUseOrderedIngress() {
		t.Fatal("expected QUIC Initial on allowlisted port to use ordered ingress")
	}
	if got := decision.DispatchStrategy(); got != StrategyOrderedIngress {
		t.Fatalf("DispatchStrategy() = %v, want %v", got, StrategyOrderedIngress)
	}
}

func TestOrderedDispatchStillAllowsCrossFlowConcurrency(t *testing.T) {
	pool := NewUdpTaskPool()

	decision := ClassifyUdpFlow(
		mustParseAddrPort("192.168.1.10:40200"),
		mustParseAddrPort("203.0.113.50:27015"),
		[]byte{0x01, 0x02},
	)
	if decision.DispatchStrategy() != StrategyOrderedIngress {
		t.Fatalf("DispatchStrategy() = %v, want %v", decision.DispatchStrategy(), StrategyOrderedIngress)
	}

	var running atomic.Int64
	var peak atomic.Int64
	var wg sync.WaitGroup
	release := make(chan struct{})

	keys := []UdpFlowKey{
		NewUdpFlowKey(
			mustParseAddrPort("192.168.1.10:40200"),
			mustParseAddrPort("203.0.113.50:27015"),
		),
		NewUdpFlowKey(
			mustParseAddrPort("192.168.1.10:40201"),
			mustParseAddrPort("203.0.113.51:27015"),
		),
	}

	for _, key := range keys {
		wg.Add(1)
		pool.EmitTask(key, func() {
			defer wg.Done()
			cur := running.Add(1)
			defer running.Add(-1)
			for {
				old := peak.Load()
				if cur <= old || peak.CompareAndSwap(old, cur) {
					break
				}
			}
			<-release
		})
	}

	waitForCondition(t, time.Second, "both per-flow convoys active", func() bool {
		return peak.Load() >= 2
	})
	close(release)
	wg.Wait()

	if peak.Load() <= 1 {
		t.Fatalf("expected ordered ingress to stay per-flow rather than global, peak=%d", peak.Load())
	}
}

func TestUdpTaskPool_PreservesPerFlowOrderAcrossOverflow(t *testing.T) {
	pool := NewUdpTaskPool()
	key := NewUdpFlowKey(
		mustParseAddrPort("192.168.1.10:40300"),
		mustParseAddrPort("203.0.113.60:27015"),
	)

	const total = UdpTaskQueueLength + 64

	var (
		mu   sync.Mutex
		got  = make([]int, 0, total)
		done sync.WaitGroup
	)
	done.Add(total)

	for i := 0; i < total; i++ {
		seq := i
		pool.EmitTask(key, func() {
			defer done.Done()
			mu.Lock()
			got = append(got, seq)
			mu.Unlock()
			time.Sleep(50 * time.Microsecond)
		})
	}

	done.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(got) != total {
		t.Fatalf("executed %d tasks, want %d", len(got), total)
	}
	for i, seq := range got {
		if seq != i {
			t.Fatalf("got execution order[%d]=%d, want %d", i, seq, i)
		}
	}
}

func TestUdpEndpointFullConeResponseCacheByBindAddr(t *testing.T) {
	ue := &UdpEndpoint{}
	bindA := netip.MustParseAddrPort("127.0.0.1:20001")
	bindB := netip.MustParseAddrPort("127.0.0.1:20002")
	connA := &Anyfrom{}
	connB := &Anyfrom{}

	ue.StoreCachedResponseConn(bindA, connA)
	ue.StoreCachedResponseConn(bindB, connB)

	if got := ue.CachedResponseConn(bindA); got != connA {
		t.Fatalf("CachedResponseConn(bindA) = %p, want %p", got, connA)
	}
	if got := ue.CachedResponseConn(bindB); got != connB {
		t.Fatalf("CachedResponseConn(bindB) = %p, want %p", got, connB)
	}

	ue.ClearCachedResponseConn(bindA, connA)
	if got := ue.CachedResponseConn(bindA); got != nil {
		t.Fatalf("CachedResponseConn(bindA) after clear = %p, want nil", got)
	}
	if got := ue.CachedResponseConn(bindB); got != connB {
		t.Fatalf("CachedResponseConn(bindB) after clearing A = %p, want %p", got, connB)
	}
	if got := ue.responseConnSlot(); got != nil {
		t.Fatal("full-cone endpoint should not expose single-slot response cache")
	}
}
