// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// BenchmarkUdpProxyDial measures the cost of the proxy-dial slow path under
// UdpEndpointPool.GetOrCreate: no other benchmark exercises DialContext
// through the proxy dialer under UDP traffic.
//
// Two cache regimes are compared:
//
//   - cache=miss: each iteration targets a fresh flow key so GetOrCreate takes
//     the slow path and actually performs a proxy dial.
//   - cache=hit:  the same flow key is reused so GetOrCreate resolves through
//     the shard lookup and skips dialing entirely.
func BenchmarkUdpProxyDial(b *testing.B) {
	for _, cache := range []struct {
		name string
		miss bool
	}{
		{name: "cache=miss", miss: true},
		{name: "cache=hit", miss: false},
	} {
		b.Run(cache.name, func(b *testing.B) {
			runUdpProxyDialBenchmark(b, cache.miss)
		})
	}
}

func runUdpProxyDialBenchmark(b *testing.B, miss bool) {
	restore := setupQuicInitialRegressionTestState(b)
	b.Cleanup(restore)

	// A factory dialer mints one simulation conn per dial so cache-miss
	// iterations each get a fresh transport. Close on one conn must not tear
	// down a sibling that a concurrent lookup might still observe.
	dialer, underlay := newFactoryProxyEndpointDialer("hysteria2", "proxy.example:443", func() netproxy.Conn {
		return &udpReuseSimulationConn{
			reads:   make(chan scriptedPacketRead, 1),
			closeCh: make(chan struct{}),
		}
	})

	handler := func(*UdpEndpoint, []byte, netip.AddrPort) error { return nil }
	getDialOption := func(context.Context) (*DialOption, error) {
		return &DialOption{
			Dialer:  dialer,
			Network: "udp",
			Target:  "[2001:db8::1]:443",
		}, nil
	}

	baseSrc := netip.MustParseAddrPort("192.0.2.10:40000")
	dst := netip.MustParseAddrPort("203.0.113.30:443")
	// keyForOp returns a unique key per op for cache=miss. The source port
	// space alone wraps at 64k (uint16), which collides well before benchmark
	// scales; vary the source address octet too so the keys stay unique across
	// the full b.N range without consuming real address space.
	keyForOp := func(op int) UdpEndpointKey {
		if !miss {
			return UdpEndpointKey{Src: baseSrc, Dst: dst}
		}
		srcAddr := netip.AddrFrom4([4]byte{
			192, 0, 2, byte(2 + (op >> 16)),
		})
		src := netip.AddrPortFrom(srcAddr, uint16(40000+(op&0xffff)))
		return UdpEndpointKey{Src: src, Dst: dst}
	}

	var created []*UdpEndpoint
	b.Cleanup(func() {
		for _, ue := range created {
			closeQuicBenchmarkEndpoint(b, ue)
		}
	})

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for op := range b.N {
		key := keyForOp(op)
		opts := &UdpEndpointOptions{
			Ctx:           ctx,
			Handler:       handler,
			NatTimeout:    5 * time.Second,
			GetDialOption: getDialOption,
		}
		ue, _, err := DefaultUdpEndpointPool.GetOrCreate(key, opts)
		if err != nil {
			b.Fatalf("GetOrCreate op %d: %v", op, err)
		}
		if miss {
			// Cache-miss iterations create a fresh endpoint that must be torn
			// down so the pool does not accumulate dead entries across b.N.
			created = append(created, ue)
		}
	}
	b.StopTimer()

	// Sanity: cache-miss must dial once per op; cache-hit must dial exactly
	// once (the initial population). GetOrCreate owns the dial; the first-
	// packet write happens later in handlePkt and is therefore out of scope for
	// this benchmark's dial-cost measurement.
	wantDials := int32(1)
	if miss {
		wantDials = int32(b.N)
	}
	if got := underlay.calls.Load(); got != wantDials {
		b.Fatalf("proxy DialContext count = %d, want %d", got, wantDials)
	}
}

// closeQuicBenchmarkEndpoint closes a benchmark endpoint with a timeout so a
// hung Close fails the benchmark instead of deadlocking teardown.
func closeQuicBenchmarkEndpoint(tb testing.TB, ue *UdpEndpoint) {
	if ue == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_ = ue.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		tb.Errorf("UdpEndpoint.Close hung during benchmark teardown")
	}
}
