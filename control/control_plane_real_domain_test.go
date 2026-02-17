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

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/netproxy"
)

func newTestControlPlaneForRealDomainProbe() *ControlPlane {
	return &ControlPlane{
		realDomainSet: bloom.NewWithEstimates(2048, 0.001),
		soMarkFromDae: 0,
		mptcp:         false,
	}
}

func TestIsRealDomain_NegativeCacheAvoidsRepeatedProbe(t *testing.T) {
	oldTTL := realDomainNegativeCacheTTL
	oldSystemDNS := systemDnsForRealDomainProbe
	oldResolver := resolveIp46ForRealDomainProbe
	defer func() {
		realDomainNegativeCacheTTL = oldTTL
		systemDnsForRealDomainProbe = oldSystemDNS
		resolveIp46ForRealDomainProbe = oldResolver
	}()

	realDomainNegativeCacheTTL = 200 * time.Millisecond
	systemDnsForRealDomainProbe = func() (netip.AddrPort, error) {
		return netip.MustParseAddrPort("1.1.1.1:53"), nil
	}

	var calls atomic.Int32
	resolveIp46ForRealDomainProbe = func(ctx context.Context, dialer netproxy.Dialer, dns netip.AddrPort, host string, network string, race bool) (*netutils.Ip46, error, error) {
		calls.Add(1)
		return &netutils.Ip46{}, nil, nil
	}

	cp := newTestControlPlaneForRealDomainProbe()
	domain := "negative-cache-hit.example"

	if cp.isRealDomain(domain) {
		t.Fatal("expected non-real domain")
	}
	if cp.isRealDomain(domain) {
		t.Fatal("expected non-real domain on cached negative hit")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected one probe with negative cache hit, got %d", got)
	}
}

func TestIsRealDomain_NegativeCacheExpiresAndReprobe(t *testing.T) {
	oldTTL := realDomainNegativeCacheTTL
	oldSystemDNS := systemDnsForRealDomainProbe
	oldResolver := resolveIp46ForRealDomainProbe
	defer func() {
		realDomainNegativeCacheTTL = oldTTL
		systemDnsForRealDomainProbe = oldSystemDNS
		resolveIp46ForRealDomainProbe = oldResolver
	}()

	realDomainNegativeCacheTTL = 15 * time.Millisecond
	systemDnsForRealDomainProbe = func() (netip.AddrPort, error) {
		return netip.MustParseAddrPort("1.1.1.1:53"), nil
	}

	var calls atomic.Int32
	resolveIp46ForRealDomainProbe = func(ctx context.Context, dialer netproxy.Dialer, dns netip.AddrPort, host string, network string, race bool) (*netutils.Ip46, error, error) {
		calls.Add(1)
		return &netutils.Ip46{}, nil, nil
	}

	cp := newTestControlPlaneForRealDomainProbe()
	domain := "negative-cache-expire.example"

	if cp.isRealDomain(domain) {
		t.Fatal("expected non-real domain")
	}
	time.Sleep(realDomainNegativeCacheTTL + 10*time.Millisecond)
	if cp.isRealDomain(domain) {
		t.Fatal("expected non-real domain after cache expiry")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected reprobe after negative cache expiry, got %d calls", got)
	}
}

func TestIsRealDomain_ConcurrentProbeDeduplicated(t *testing.T) {
	oldTTL := realDomainNegativeCacheTTL
	oldSystemDNS := systemDnsForRealDomainProbe
	oldResolver := resolveIp46ForRealDomainProbe
	defer func() {
		realDomainNegativeCacheTTL = oldTTL
		systemDnsForRealDomainProbe = oldSystemDNS
		resolveIp46ForRealDomainProbe = oldResolver
	}()

	realDomainNegativeCacheTTL = 200 * time.Millisecond
	systemDnsForRealDomainProbe = func() (netip.AddrPort, error) {
		return netip.MustParseAddrPort("1.1.1.1:53"), nil
	}

	var calls atomic.Int32
	resolveIp46ForRealDomainProbe = func(ctx context.Context, dialer netproxy.Dialer, dns netip.AddrPort, host string, network string, race bool) (*netutils.Ip46, error, error) {
		calls.Add(1)
		time.Sleep(30 * time.Millisecond)
		return &netutils.Ip46{}, nil, nil
	}

	cp := newTestControlPlaneForRealDomainProbe()
	domain := "singleflight-negative.example"

	const goroutines = 32
	start := make(chan struct{})
	results := make(chan bool, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			results <- cp.isRealDomain(domain)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	for r := range results {
		if r {
			t.Fatal("expected all concurrent results to be non-real")
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected single probe due to singleflight dedup, got %d", got)
	}
}

func TestIsRealDomain_PositivePathCachedInBloom(t *testing.T) {
	oldTTL := realDomainNegativeCacheTTL
	oldSystemDNS := systemDnsForRealDomainProbe
	oldResolver := resolveIp46ForRealDomainProbe
	defer func() {
		realDomainNegativeCacheTTL = oldTTL
		systemDnsForRealDomainProbe = oldSystemDNS
		resolveIp46ForRealDomainProbe = oldResolver
	}()

	realDomainNegativeCacheTTL = 200 * time.Millisecond
	systemDnsForRealDomainProbe = func() (netip.AddrPort, error) {
		return netip.MustParseAddrPort("1.1.1.1:53"), nil
	}

	var calls atomic.Int32
	resolveIp46ForRealDomainProbe = func(ctx context.Context, dialer netproxy.Dialer, dns netip.AddrPort, host string, network string, race bool) (*netutils.Ip46, error, error) {
		calls.Add(1)
		return &netutils.Ip46{Ip4: netip.MustParseAddr("93.184.216.34")}, nil, nil
	}

	cp := newTestControlPlaneForRealDomainProbe()
	domain := "positive-cache.example"

	if !cp.isRealDomain(domain) {
		t.Fatal("expected real domain on positive probe")
	}
	if !cp.isRealDomain(domain) {
		t.Fatal("expected real domain on bloom cache hit")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected positive probe to run only once, got %d", got)
	}
}
