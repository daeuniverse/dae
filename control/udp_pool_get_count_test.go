/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net/netip"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// D2 Get-count scenarios. Numbers in the table are asserted so a hot-path
// change cannot silently add lookups back. Cross-probe Gets are correctness,
// not waste; DNS fast path must stay at zero.
//
//	scenario                              before  after
//	dns_fast_path                         0       0
//	cache_hit_fullcone                    2       1   fused cache+handlePkt
//	cache_hit_sniff_eligible_cross_probe  3       3   cross-probe kept
//	cache_miss_fallback_hit               3       2   fallback key == first Get
//	binding_miss_existing_fullcone        2       2   no prefetch on binding miss
//	cache_total_miss_then_create          3       3   owner Get of new endpoint
func TestUdpIngressTaskPoolGetCountByScenario(t *testing.T) {
	for _, tc := range []struct {
		name string
		want int
		run  func(t *testing.T) []UdpEndpointKey
	}{
		{
			name: "dns_fast_path",
			want: 0,
			run:  scenarioDNSFastPathGets,
		},
		{
			name: "cache_hit_fullcone",
			want: 1, // fused cache+handlePkt Get of the src-only endpoint
			run:  scenarioCacheHitFullConeGets,
		},
		{
			name: "cache_hit_sniff_eligible_cross_probe",
			want: 3, // cache primary FullCone + handlePkt symmetric miss + src-only probe
			run:  scenarioCacheHitSniffEligibleCrossProbeGets,
		},
		{
			name: "cache_miss_fallback_hit",
			want: 2, // cache primary miss + fallback hit; fallback key == handlePkt first Get, so prefetch
			run:  scenarioCacheMissFallbackHitGets,
		},
		{
			name: "binding_miss_existing_fullcone",
			// cache primary Get (endpoint present, dst/proto binding miss) +
			// handlePkt first Get. owner Get is skipped because there is no
			// fresh BPF result to write (RetrieveRoutingResult misses).
			want: 2,
			run:  scenarioBindingMissExistingFullConeGets,
		},
		{
			name: "cache_total_miss_then_create",
			want: 3, // cache miss + handlePkt miss + owner Get of the new endpoint
			run:  scenarioCacheTotalMissThenCreateGets,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys := tc.run(t)
			if len(keys) != tc.want {
				t.Fatalf("Get count = %d, want %d; keys=%v", len(keys), tc.want, keys)
			}
			t.Logf("Gets=%d keys=%v", len(keys), formatEndpointKeys(keys))
		})
	}
}

func scenarioDNSFastPathGets(t *testing.T) []UdpEndpointKey {
	t.Helper()
	restore := swapUdpEndpointPoolForTest(t)
	defer restore()

	query := new(dnsmessage.Msg)
	query.SetQuestion("example.com.", dnsmessage.TypeA)
	payload, err := query.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	src := mustParseAddrPort("192.0.2.10:53000")
	dst := mustParseAddrPort("1.1.1.1:53")
	cp := newGetCountControlPlane(t)

	return countPoolGets(t, func() {
		runCountedIngressTask(cp, src, dst, payload)
	})
}

func scenarioCacheHitFullConeGets(t *testing.T) []UdpEndpointKey {
	t.Helper()
	restore := swapUdpEndpointPoolForTest(t)
	defer restore()

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("52.199.194.44:23002")
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	cp, routingResult := newGetCountDialingControlPlane(t)
	primeUdpEndpointViaHandlePkt(t, cp, src, dst, payload, routingResult)
	bindPooledRouting(t, ClassifyUdpFlow(src, dst, payload).FullConeNatEndpointKey(), dst, routingResult)

	return countPoolGets(t, func() {
		runCountedIngressTask(cp, src, dst, payload)
	})
}

func scenarioCacheHitSniffEligibleCrossProbeGets(t *testing.T) []UdpEndpointKey {
	t.Helper()
	restore := swapUdpEndpointPoolForTest(t)
	defer restore()

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("203.0.113.10:443")
	payload := []byte{0x01, 0x02, 0x03, 0x04} // ordinary, not QUIC Initial
	cp, routingResult := newGetCountDialingControlPlane(t)
	primeUdpEndpointViaHandlePkt(t, cp, src, dst, payload, routingResult)
	flow := ClassifyUdpFlow(src, dst, payload)
	if !flow.AllowsSniffing || flow.HasConfirmedQuicState() {
		t.Fatalf("fixture must be sniff-eligible ordinary UDP, got %+v", flow)
	}
	bindPooledRouting(t, flow.FullConeNatEndpointKey(), dst, routingResult)

	return countPoolGets(t, func() {
		runCountedIngressTask(cp, src, dst, payload)
	})
}

func scenarioCacheMissFallbackHitGets(t *testing.T) []UdpEndpointKey {
	t.Helper()
	restore := swapUdpEndpointPoolForTest(t)
	defer restore()

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("203.0.113.10:443")
	ordinary := []byte{0x01, 0x02, 0x03, 0x04}
	cp, routingResult := newGetCountDialingControlPlane(t)
	flow := ClassifyUdpFlow(src, dst, ordinary)
	if flow.HasConfirmedQuicState() || !flow.AllowsSniffing {
		t.Fatalf("fixture must be sniff-eligible ordinary UDP, got %+v", flow)
	}
	// Plant a live symmetric endpoint without going through QUIC handlePkt,
	// so ClassifyUdpFlow does not pick up a leftover sniffer session.
	insertPooledEndpoint(t, flow.SymmetricNatEndpointKey(), dst.String())
	bindPooledRouting(t, flow.SymmetricNatEndpointKey(), dst, routingResult)

	return countPoolGets(t, func() {
		runCountedIngressTask(cp, src, dst, ordinary)
	})
}

func scenarioBindingMissExistingFullConeGets(t *testing.T) []UdpEndpointKey {
	t.Helper()
	restore := swapUdpEndpointPoolForTest(t)
	defer restore()

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("52.199.194.44:23002")
	otherDst := mustParseAddrPort("52.199.194.44:23003")
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	cp, routingResult := newGetCountDialingControlPlane(t)
	primeUdpEndpointViaHandlePkt(t, cp, src, dst, payload, routingResult)
	// Bind a different original destination so Get finds the endpoint but
	// GetBoundRoutingResult misses. Missing BPF tuple then falls back to
	// userspace routing (core is nil → ErrKeyNotExist).
	bindPooledRouting(t, ClassifyUdpFlow(src, dst, payload).FullConeNatEndpointKey(), otherDst, routingResult)

	return countPoolGets(t, func() {
		runCountedIngressTask(cp, src, dst, payload)
	})
}

func scenarioCacheTotalMissThenCreateGets(t *testing.T) []UdpEndpointKey {
	t.Helper()
	restore := swapUdpEndpointPoolForTest(t)
	defer restore()

	src := mustParseAddrPort("192.168.89.3:51000")
	dst := mustParseAddrPort("52.199.194.44:23002")
	payload := []byte{0xaa, 0xbb, 0xcc}
	cp, routingResult := newGetCountDialingControlPlane(t)
	// Bypass Run()'s BPF retrieve (core is nil) so handlePkt still sees a
	// concrete outbound and creates the endpoint. Cache lookup still misses.
	return countPoolGets(t, func() {
		flowDecision := ClassifyUdpFlow(src, dst, payload)
		if err := cp.handlePktWithPrefetch(payload, src, dst, routingResult, flowDecision, nil, UdpEndpointKey{}, false); err != nil {
			t.Fatalf("handlePkt create: %v", err)
		}
		if ue := routingCacheOwnerEndpoint(flowDecision); ue != nil {
			ue.UpdateCachedRoutingResult(dst, unix.IPPROTO_UDP, routingResult)
		}
	})
}

func newGetCountControlPlane(t *testing.T) *ControlPlane {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return &ControlPlane{
		log: logger,
	}
}

func newGetCountDialingControlPlane(t *testing.T) (*ControlPlane, *bpfRoutingResult) {
	t.Helper()
	conn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d, _ := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}
	return cp, routingResult
}

func primeUdpEndpointViaHandlePkt(t *testing.T, cp *ControlPlane, src, dst netip.AddrPort, payload []byte, routingResult *bpfRoutingResult) {
	t.Helper()
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	if err := cp.handlePktWithPrefetch(payload, src, dst, routingResult, flowDecision, nil, UdpEndpointKey{}, false); err != nil {
		t.Fatalf("prime handlePkt: %v", err)
	}
}

func bindPooledRouting(t *testing.T, key UdpEndpointKey, dst netip.AddrPort, routingResult *bpfRoutingResult) {
	t.Helper()
	ue, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || ue == nil {
		t.Fatalf("expected pooled endpoint for %v", key)
	}
	ue.UpdateCachedRoutingResult(dst, unix.IPPROTO_UDP, routingResult)
}

func insertPooledEndpoint(t *testing.T, key UdpEndpointKey, dialTarget string) {
	t.Helper()
	conn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d, _ := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	ue, isNew, err := DefaultUdpEndpointPool.GetOrCreate(key, &UdpEndpointOptions{
		Handler: func(*UdpEndpoint, []byte, netip.AddrPort) error { return nil },
		GetDialOption: func(context.Context) (*DialOption, error) {
			return &DialOption{
				Dialer:  d,
				Network: "udp",
				Target:  dialTarget,
			}, nil
		},
	})
	if err != nil || !isNew || ue == nil {
		t.Fatalf("insertPooledEndpoint GetOrCreate = (%v, %v, %v)", ue, isNew, err)
	}
	ue.DialTarget = dialTarget
}

func runCountedIngressTask(cp *ControlPlane, src, dst netip.AddrPort, payload []byte) {
	buf := pool.Get(len(payload))
	copy(buf, payload)
	task := udpIngressTaskPool.Get().(*udpIngressTask)
	task.c = cp
	task.lConn = nil
	task.pktBuf = buf
	task.admission = nil
	task.realDst = dst
	task.convergeSrc = src
	task.flowDecision = ClassifyUdpFlow(src, dst, payload)
	task.Run()
}

func swapUdpEndpointPoolForTest(t *testing.T) func() {
	t.Helper()
	old := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	return func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = old
	}
}

func countPoolGets(t *testing.T, fn func()) []UdpEndpointKey {
	t.Helper()
	var mu sync.Mutex
	var keys []UdpEndpointKey
	udpEndpointPoolGetObserver = func(key UdpEndpointKey) {
		mu.Lock()
		keys = append(keys, key)
		mu.Unlock()
	}
	defer func() { udpEndpointPoolGetObserver = nil }()
	fn()
	return keys
}

func formatEndpointKeys(keys []UdpEndpointKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Src.String()+"->"+k.Dst.String())
	}
	return out
}

func TestLookupCachedRoutingBinding_PrefetchAndFallback(t *testing.T) {
	restore := swapUdpEndpointPoolForTest(t)
	defer restore()

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("203.0.113.10:443")
	otherDst := mustParseAddrPort("203.0.113.10:8443")
	ordinary := []byte{0x01, 0x02, 0x03, 0x04}
	routingResult := &bpfRoutingResult{Outbound: 2, Mark: 9}
	flow := ClassifyUdpFlow(src, dst, ordinary)
	if !flow.AllowsSniffing || flow.HasConfirmedQuicState() {
		t.Fatalf("fixture must be sniff-eligible ordinary UDP, got %+v", flow)
	}

	fullConeKey := flow.FullConeNatEndpointKey()
	symmetricKey := flow.SymmetricNatEndpointKey()
	insertPooledEndpoint(t, fullConeKey, dst.String())
	insertPooledEndpoint(t, symmetricKey, dst.String())

	t.Run("binding_miss_falls_back", func(t *testing.T) {
		bindPooledRouting(t, fullConeKey, otherDst, routingResult)
		bindPooledRouting(t, symmetricKey, dst, routingResult)
		lookup := lookupCachedRoutingBinding(flow, dst)
		if !lookup.bindingHit || lookup.bound == nil {
			t.Fatal("expected fallback binding hit")
		}
		if lookup.bound.Mark != routingResult.Mark || lookup.bound.Outbound != routingResult.Outbound {
			t.Fatalf("bound result = %+v, want %+v", lookup.bound, routingResult)
		}
		if lookup.owner == nil {
			t.Fatal("fallback owner must be the symmetric endpoint")
		}
		if !lookup.prefetchOK || lookup.prefetchKey != symmetricKey {
			t.Fatal("sniff-eligible first Get is the symmetric key; fallback hit should prefetch")
		}
	})

	t.Run("primary_binding_miss_fallback_miss_keeps_owner", func(t *testing.T) {
		bindPooledRouting(t, fullConeKey, otherDst, routingResult)
		// Symmetric endpoint exists but is bound to a different dst, so
		// fallback Get hits and GetBoundRoutingResult still misses.
		bindPooledRouting(t, symmetricKey, otherDst, routingResult)
		lookup := lookupCachedRoutingBinding(flow, dst)
		if lookup.bindingHit {
			t.Fatal("expected no dst+proto binding for this destination")
		}
		if lookup.prefetchOK {
			t.Fatal("binding miss must not prefetch")
		}
		if lookup.owner == nil {
			t.Fatal("owner must remain a live endpoint so a later cache write can land")
		}
	})

	t.Run("fullcone_hit_does_not_prefetch_when_handlepkt_starts_symmetric", func(t *testing.T) {
		bindPooledRouting(t, fullConeKey, dst, routingResult)
		lookup := lookupCachedRoutingBinding(flow, dst)
		if !lookup.bindingHit {
			t.Fatal("expected primary full-cone binding hit")
		}
		if lookup.prefetchOK {
			t.Fatal("sniff-eligible handlePkt first key is symmetric; prefetch would skip the cross-probe")
		}
		nonSniff := ClassifyUdpFlow(src, mustParseAddrPort("52.199.194.44:23002"), ordinary)
		if !canPrefetchCachedEndpoint(nonSniff, nonSniff.FullConeNatEndpointKey()) {
			t.Fatal("non-sniff UDP first Get is src-only; prefetch should be allowed")
		}
		if canPrefetchCachedEndpoint(flow, fullConeKey) {
			t.Fatal("sniff-eligible first Get is symmetric; FullCone key must not prefetch")
		}
	})
}
