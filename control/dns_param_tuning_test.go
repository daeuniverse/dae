/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 *
 * Parameter tuning tests for DNS optimization.
 * These tests help find optimal values for latency-sensitive parameters.
 */

package control

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// ==============================================================================
// Test 1: DnsCacheRouteRefreshInterval - eBPF map update frequency
// ==============================================================================
// Theory:
// - Lower value: More frequent updates, higher CPU, fresher routing
// - Higher value: Less overhead, but stale routing may occur
// - Sweet spot: Balance between freshness and overhead
// ==============================================================================

func TestParamTuning_RouteRefreshInterval(t *testing.T) {
	testCases := []struct {
		name     string
		interval time.Duration
	}{
		{"500ms", 500 * time.Millisecond},
		{"1s", 1 * time.Second},
		{"2s", 2 * time.Second},
		{"3s", 3 * time.Second},
		{"5s", 5 * time.Second},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			oldInterval := DnsCacheRouteRefreshInterval
			DnsCacheRouteRefreshInterval = tc.interval
			defer func() { DnsCacheRouteRefreshInterval = oldInterval }()

			// Simulate 1000 cache accesses
			var callbackCount atomic.Int32
			controller := &DnsController{
				log:        logrus.New(),
				dnsCache:   sync.Map{},
				cacheAccessCallback: func(cache *DnsCache) error {
					callbackCount.Add(1)
					return nil
				},
			}

			// Pre-populate cache
			cache := &DnsCache{
				Deadline: time.Now().Add(10 * time.Second),
				Answer: []dnsmessage.RR{
					&dnsmessage.A{
						Hdr: dnsmessage.RR_Header{Name: "test.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 10},
						A:   netip.MustParseAddr("1.2.3.4").AsSlice(),
					},
				},
			}
			controller.dnsCache.Store("test.com.1", cache)

			start := time.Now()
			iterations := 1000

			for i := 0; i < iterations; i++ {
				controller.LookupDnsRespCache("test.com.1", false)
				time.Sleep(time.Microsecond) // Simulate real-world spacing
			}

			elapsed := time.Since(start)
			callbacks := callbackCount.Load()

			// Calculate metrics
			expectedRefreshes := int(elapsed / tc.interval)
			if expectedRefreshes == 0 {
				expectedRefreshes = 1 // At least one refresh should occur
			}

			t.Logf("Interval: %v, Duration: %v, Callbacks: %d, Expected: ~%d, RefreshRate: %.2f/s",
				tc.interval, elapsed.Round(time.Millisecond), callbacks, expectedRefreshes,
				float64(callbacks)/elapsed.Seconds())

			// The callback count should be roughly proportional to interval
			// Higher interval = fewer callbacks = lower overhead
		})
	}
}

// ==============================================================================
// Test 2: realDomainProbeTimeout - First paint latency impact
// ==============================================================================
// Theory:
// - Lower value: Faster fallback, but may miss slow legitimate responses
// - Higher value: More reliable detection, but increases first paint latency
// - Sweet spot: Fast enough for UX, reliable enough for accuracy
// ==============================================================================

func TestParamTuning_RealDomainProbeTimeout(t *testing.T) {
	testCases := []struct {
		name    string
		timeout time.Duration
	}{
		{"200ms", 200 * time.Millisecond},
		{"300ms", 300 * time.Millisecond},
		{"500ms", 500 * time.Millisecond},
		{"800ms", 800 * time.Millisecond},
		{"1000ms", 1000 * time.Millisecond},
	}

	// Simulate different network latencies
	networkLatencies := []struct {
		name    string
		latency time.Duration
	}{
		{"Fast (50ms)", 50 * time.Millisecond},
		{"Normal (150ms)", 150 * time.Millisecond},
		{"Slow (400ms)", 400 * time.Millisecond},
		{"VerySlow (700ms)", 700 * time.Millisecond},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			oldTimeout := realDomainProbeTimeout
			realDomainProbeTimeout = tc.timeout
			defer func() { realDomainProbeTimeout = oldTimeout }()

			for _, netLat := range networkLatencies {
				t.Run(netLat.name, func(t *testing.T) {
					// Simulate probe with network latency
					start := time.Now()

					ctx, cancel := context.WithTimeout(context.Background(), realDomainProbeTimeout)
					defer cancel()

					// Simulate DNS resolution
					done := make(chan bool, 1)
					go func() {
						time.Sleep(netLat.latency)
						done <- true
					}()

					var success bool
					select {
					case <-done:
						success = true
					case <-ctx.Done():
						success = false
					}

					elapsed := time.Since(start)
					userWaitTime := elapsed
					if !success {
						userWaitTime = realDomainProbeTimeout // User waits full timeout on failure
					}

					result := "SUCCESS"
					if !success {
						result = "TIMEOUT"
					}

					t.Logf("Network: %v, Timeout: %v, Result: %s, WaitTime: %v",
						netLat.latency, tc.timeout, result, userWaitTime.Round(time.Millisecond))
				})
			}
		})
	}
}

// ==============================================================================
// Test 3: dnsDialerSnapshotTTL - Dialer selection overhead
// ==============================================================================
// Theory:
// - Lower value: Fresher dialer selection, but more overhead
// - Higher value: Less overhead, but may use stale dialer
// - Sweet spot: Cache long enough to reduce overhead, short enough for accuracy
// ==============================================================================

func TestParamTuning_DnsDialerSnapshotTTL(t *testing.T) {
	testCases := []struct {
		name string
		ttl  time.Duration
	}{
		{"100ms", 100 * time.Millisecond},
		{"250ms", 250 * time.Millisecond},
		{"500ms", 500 * time.Millisecond},
		{"750ms", 750 * time.Millisecond},
		{"1000ms", 1000 * time.Millisecond},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			oldTTL := dnsDialerSnapshotTTL
			dnsDialerSnapshotTTL = tc.ttl
			defer func() { dnsDialerSnapshotTTL = oldTTL }()

			cp := &ControlPlane{}

			req := &udpRequest{
				realSrc: netip.MustParseAddrPort("10.0.0.2:12345"),
				routingResult: &bpfRoutingResult{
					Dscp:  1,
					Mac:   [6]uint8{1, 2, 3, 4, 5, 6},
					Pname: [16]uint8{'t', 'e', 's', 't'},
				},
			}

			upstream := &dns.Upstream{
				Scheme:   dns.UpstreamScheme_UDP,
				Hostname: "dns.example",
				Port:     53,
				Ip46: &netutils.Ip46{
					Ip4: netip.MustParseAddr("1.1.1.1"),
				},
			}

			key, ok := buildDnsDialerSnapshotKey(req, upstream)
			if !ok {
				t.Fatal("Failed to build snapshot key")
			}

			dialArg := &dialArgument{
				l4proto:    consts.L4ProtoStr_UDP,
				ipversion:  consts.IpVersionStr_4,
				bestTarget: netip.MustParseAddrPort("1.1.1.1:53"),
			}

			// Simulate burst of 100 requests
			start := time.Now()
			burstSize := 100
			cacheHits := 0

			for i := 0; i < burstSize; i++ {
				now := start.Add(time.Duration(i) * 5 * time.Millisecond)

				// First request stores
				if i == 0 {
					cp.storeDnsDialerSnapshot(key, dialArg, now)
				}

				// Try to load
				if cached, hit := cp.loadDnsDialerSnapshot(key, now); hit {
					cacheHits++
					if cached == nil {
						t.Error("Cached dialArg is nil")
					}
				} else if i > 0 {
					// Cache miss after first request - TTL expired
					cp.storeDnsDialerSnapshot(key, dialArg, now)
				}
			}

			elapsed := time.Since(start)
			hitRate := float64(cacheHits) / float64(burstSize) * 100

			t.Logf("TTL: %v, Requests: %d, CacheHits: %d, HitRate: %.1f%%, Overhead: %v",
				tc.ttl, burstSize, cacheHits, hitRate, elapsed.Round(time.Microsecond))

			// Higher TTL should result in higher cache hit rate for burst requests
		})
	}
}

// ==============================================================================
// Test 4: UDP Connection Pool maxIdleTime - Connection reuse
// ==============================================================================
// Theory:
// - Lower value: More connection churn, but fresher connections
// - Higher value: Better reuse, but risk of stale connections/packets
// - Sweet spot: Long enough for reuse, short enough to avoid stale issues
// ==============================================================================

func TestParamTuning_UdpConnPoolMaxIdleTime(t *testing.T) {
	testCases := []struct {
		name       string
		maxIdle    time.Duration
		idlePeriod time.Duration // Time between requests
	}{
		{"15s_Idle10s", 15 * time.Second, 10 * time.Second},
		{"30s_Idle10s", 30 * time.Second, 10 * time.Second},
		{"30s_Idle20s", 30 * time.Second, 20 * time.Second},
		{"60s_Idle10s", 60 * time.Second, 10 * time.Second},
		{"60s_Idle30s", 60 * time.Second, 30 * time.Second},
		{"60s_Idle45s", 60 * time.Second, 45 * time.Second},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var dialCount atomic.Int32
			pool := newUdpConnPoolWithIdleTime(8, func(ctx context.Context) (netproxy.Conn, error) {
				dialCount.Add(1)
				return &mockNetConn{}, nil
			}, tc.maxIdle)

			// Simulate request pattern
			ctx := context.Background()

			// First request - always new connection
			conn1, _ := pool.get(ctx)
			pool.put(conn1)
			initialDials := dialCount.Load()

			// Simulate idle period
			time.Sleep(50 * time.Millisecond) // Short sleep for test

			// Second request after idle - depends on maxIdleTime
			// For testing, we manually check the logic
			connWithTime := &udpConnWithTimestamp{
				conn:     conn1,
				lastUsed: time.Now().Add(-tc.idlePeriod),
			}

			shouldReuse := time.Since(connWithTime.lastUsed) <= tc.maxIdle

			t.Logf("MaxIdle: %v, IdlePeriod: %v, ShouldReuse: %v, InitialDials: %d",
				tc.maxIdle, tc.idlePeriod, shouldReuse, initialDials)

			pool.close()
		})
	}
}

// Helper: newUdpConnPoolWithIdleTime creates a pool with custom idle time
func newUdpConnPoolWithIdleTime(maxIdle int, dialer func(context.Context) (netproxy.Conn, error), maxIdleTime time.Duration) *udpConnPool {
	return &udpConnPool{
		idleConns:   make(chan *udpConnWithTimestamp, maxIdle),
		dialer:      dialer,
		maxIdleTime: maxIdleTime,
	}
}

// mockNetConn implements netproxy.Conn for testing
type mockNetConn struct{}

func (m *mockNetConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockNetConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockNetConn) Close() error                       { return nil }
func (m *mockNetConn) LocalAddr() net.Addr                { return nil }
func (m *mockNetConn) RemoteAddr() net.Addr               { return nil }
func (m *mockNetConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockNetConn) SetWriteDeadline(t time.Time) error { return nil }

// ==============================================================================
// Test 5: Comprehensive latency simulation
// ==============================================================================

func TestParamTuning_ComprehensiveLatencySimulation(t *testing.T) {
	// Test different parameter combinations
	combos := []struct {
		name           string
		refresh        time.Duration
		probeTimeout   time.Duration
		snapshotTTL    time.Duration
		udpMaxIdle     time.Duration
	}{
		{"Conservative", 1 * time.Second, 800 * time.Millisecond, 250 * time.Millisecond, 30 * time.Second},
		{"Balanced", 2 * time.Second, 500 * time.Millisecond, 500 * time.Millisecond, 45 * time.Second},
		{"Aggressive", 3 * time.Second, 300 * time.Millisecond, 750 * time.Millisecond, 60 * time.Second},
		{"VeryAggressive", 5 * time.Second, 200 * time.Millisecond, 1000 * time.Millisecond, 90 * time.Second},
	}

	// Simulate different scenarios (optimized for faster testing)
	scenarios := []struct {
		name          string
		dnsLatency    time.Duration
		requestCount  int
		burstInterval time.Duration
	}{
		{"ColdStart_FastNet", 5 * time.Millisecond, 10, 1 * time.Millisecond},
		{"ColdStart_SlowNet", 20 * time.Millisecond, 10, 1 * time.Millisecond},
		{"Sustained_FastNet", 5 * time.Millisecond, 50, 1 * time.Millisecond},
		{"Sustained_SlowNet", 20 * time.Millisecond, 50, 1 * time.Millisecond},
		{"Bursty_FastNet", 5 * time.Millisecond, 30, 0 * time.Millisecond},
	}

	for _, combo := range combos {
		t.Run(combo.name, func(t *testing.T) {
			for _, scenario := range scenarios {
				t.Run(scenario.name, func(t *testing.T) {
					// Set parameters
					oldRefresh := DnsCacheRouteRefreshInterval
					oldProbe := realDomainProbeTimeout
					oldSnapshot := dnsDialerSnapshotTTL
					DnsCacheRouteRefreshInterval = combo.refresh
					realDomainProbeTimeout = combo.probeTimeout
					dnsDialerSnapshotTTL = combo.snapshotTTL
					defer func() {
						DnsCacheRouteRefreshInterval = oldRefresh
						realDomainProbeTimeout = oldProbe
						dnsDialerSnapshotTTL = oldSnapshot
					}()

					// Simulate requests
					start := time.Now()
					totalLatency := time.Duration(0)

					for i := 0; i < scenario.requestCount; i++ {
						reqStart := time.Now()

						// Simulate DNS lookup latency
						time.Sleep(scenario.dnsLatency)

						// Simulate route refresh check (occasionally triggers)
						if i%10 == 0 {
							// Small overhead for route refresh check
							time.Sleep(time.Microsecond * 10)
						}

						reqLatency := time.Since(reqStart)
						totalLatency += reqLatency

						if i < scenario.requestCount-1 {
							time.Sleep(scenario.burstInterval)
						}
					}

					totalTime := time.Since(start)
					avgLatency := totalLatency / time.Duration(scenario.requestCount)
					throughput := float64(scenario.requestCount) / totalTime.Seconds()

					t.Logf("Combo: %s, Scenario: %s, Total: %v, AvgLatency: %v, Throughput: %.1f req/s",
						combo.name, scenario.name,
						totalTime.Round(time.Millisecond),
						avgLatency.Round(time.Microsecond),
						throughput)
				})
			}
		})
	}
}

// ==============================================================================
// Benchmark tests for parameter impact
// ==============================================================================

func BenchmarkRouteRefresh_1s(b *testing.B) {
	benchmarkRouteRefresh(b, 1*time.Second)
}

func BenchmarkRouteRefresh_2s(b *testing.B) {
	benchmarkRouteRefresh(b, 2*time.Second)
}

func BenchmarkRouteRefresh_5s(b *testing.B) {
	benchmarkRouteRefresh(b, 5*time.Second)
}

func benchmarkRouteRefresh(b *testing.B, interval time.Duration) {
	oldInterval := DnsCacheRouteRefreshInterval
	DnsCacheRouteRefreshInterval = interval
	defer func() { DnsCacheRouteRefreshInterval = oldInterval }()

	controller := &DnsController{
		log:      logrus.New(),
		dnsCache: sync.Map{},
		cacheAccessCallback: func(cache *DnsCache) error {
			return nil
		},
	}

	cache := &DnsCache{
		Deadline: time.Now().Add(10 * time.Second),
	}
	controller.dnsCache.Store("test.com.1", cache)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		controller.LookupDnsRespCache("test.com.1", false)
	}
}

func BenchmarkDialerSnapshot_250ms(b *testing.B) {
	benchmarkDialerSnapshot(b, 250*time.Millisecond)
}

func BenchmarkDialerSnapshot_500ms(b *testing.B) {
	benchmarkDialerSnapshot(b, 500*time.Millisecond)
}

func BenchmarkDialerSnapshot_1000ms(b *testing.B) {
	benchmarkDialerSnapshot(b, 1000*time.Millisecond)
}

func benchmarkDialerSnapshot(b *testing.B, ttl time.Duration) {
	oldTTL := dnsDialerSnapshotTTL
	dnsDialerSnapshotTTL = ttl
	defer func() { dnsDialerSnapshotTTL = oldTTL }()

	cp := &ControlPlane{}

	req := &udpRequest{
		realSrc: netip.MustParseAddrPort("10.0.0.2:12345"),
		routingResult: &bpfRoutingResult{
			Dscp: 1,
			Mac:  [6]uint8{1, 2, 3, 4, 5, 6},
		},
	}

	upstream := &dns.Upstream{
		Scheme:   dns.UpstreamScheme_UDP,
		Hostname: "dns.example",
		Port:     53,
		Ip46: &netutils.Ip46{
			Ip4: netip.MustParseAddr("1.1.1.1"),
		},
	}

	key, _ := buildDnsDialerSnapshotKey(req, upstream)
	dialArg := &dialArgument{
		l4proto:    consts.L4ProtoStr_UDP,
		ipversion:  consts.IpVersionStr_4,
		bestTarget: netip.MustParseAddrPort("1.1.1.1:53"),
	}
	cp.storeDnsDialerSnapshot(key, dialArg, time.Now())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cp.loadDnsDialerSnapshot(key, time.Now())
	}
}
