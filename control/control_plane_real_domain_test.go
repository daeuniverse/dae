/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

func newTestControlPlaneForRealDomainProbe() *ControlPlane {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return &ControlPlane{
		realDomainSet: bloom.NewWithEstimates(2048, 0.001),
		log:           log,
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

func TestIsIPLikeDomain(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		isLike bool
	}{
		{name: "ipv4", input: "1.2.3.4", isLike: true},
		{name: "ipv6-bracket", input: "[2606:4700:4700::1111]", isLike: true},
		{name: "ipv4-hostport", input: "1.2.3.4:443", isLike: true},
		{name: "ipv6-hostport", input: "[2606:4700:4700::1111]:443", isLike: true},
		{name: "domain", input: "example.com", isLike: false},
		{name: "domain-hostport", input: "example.com:443", isLike: false},
		{name: "empty", input: "", isLike: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isIPLikeDomain(tt.input); got != tt.isLike {
				t.Fatalf("isIPLikeDomain(%q)=%v, want %v", tt.input, got, tt.isLike)
			}
		})
	}
}

func TestChooseDialTarget_DomainMode_IPLikeSkipsProbe(t *testing.T) {
	oldSystemDNS := systemDnsForRealDomainProbe
	oldResolver := resolveIp46ForRealDomainProbe
	defer func() {
		systemDnsForRealDomainProbe = oldSystemDNS
		resolveIp46ForRealDomainProbe = oldResolver
	}()

	var calls atomic.Int32
	systemDnsForRealDomainProbe = func() (netip.AddrPort, error) {
		calls.Add(1)
		return netip.MustParseAddrPort("1.1.1.1:53"), nil
	}
	resolveIp46ForRealDomainProbe = func(ctx context.Context, dialer netproxy.Dialer, dns netip.AddrPort, host string, network string, race bool) (*netutils.Ip46, error, error) {
		calls.Add(1)
		return &netutils.Ip46{}, nil, nil
	}

	cp := newTestControlPlaneForRealDomainProbe()
	cp.dialMode = consts.DialMode_Domain
	cp.dnsController = &DnsController{dnsCache: sync.Map{}}

	dst := netip.MustParseAddrPort("8.8.8.8:443")
	_, _, _ = cp.ChooseDialTarget(consts.OutboundUserDefinedMin, dst, "1.2.3.4")
	_, _, _ = cp.ChooseDialTarget(consts.OutboundUserDefinedMin, dst, "1.2.3.4:443")
	_, _, _ = cp.ChooseDialTarget(consts.OutboundUserDefinedMin, dst, "[2606:4700:4700::1111]:443")

	if got := calls.Load(); got != 0 {
		t.Fatalf("expected ip-like domains to skip probe, got %d probe calls", got)
	}
}

func TestChooseDialTarget_DomainMode_UnknownDomainDoesNotBlock(t *testing.T) {
	oldTimeout := realDomainProbeTimeout
	oldSystemDNS := systemDnsForRealDomainProbe
	oldResolver := resolveIp46ForRealDomainProbe
	defer func() {
		realDomainProbeTimeout = oldTimeout
		systemDnsForRealDomainProbe = oldSystemDNS
		resolveIp46ForRealDomainProbe = oldResolver
	}()

	realDomainProbeTimeout = 500 * time.Millisecond
	systemDnsForRealDomainProbe = func() (netip.AddrPort, error) {
		return netip.MustParseAddrPort("1.1.1.1:53"), nil
	}

	started := make(chan struct{}, 1)
	unblock := make(chan struct{})
	resolveIp46ForRealDomainProbe = func(ctx context.Context, dialer netproxy.Dialer, dns netip.AddrPort, host string, network string, race bool) (*netutils.Ip46, error, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-unblock
		return &netutils.Ip46{Ip4: netip.MustParseAddr("93.184.216.34")}, nil, nil
	}

	cp := newTestControlPlaneForRealDomainProbe()
	cp.dialMode = consts.DialMode_Domain
	cp.dnsController = &DnsController{dnsCache: sync.Map{}}

	dst := netip.MustParseAddrPort("8.8.8.8:443")

	begin := time.Now()
	_, reroute, _ := cp.ChooseDialTarget(consts.OutboundUserDefinedMin, dst, "youtube.com")
	elapsed := time.Since(begin)

	if reroute {
		t.Fatal("first unknown domain request should not reroute before warm-up")
	}
	if elapsed > 60*time.Millisecond {
		t.Fatalf("first unknown domain request should not block probe, elapsed=%v", elapsed)
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("expected async probe to be triggered")
	}

	close(unblock)
}

func TestChooseDialTarget_DomainMode_WarmupEnablesReroute(t *testing.T) {
	oldTimeout := realDomainProbeTimeout
	oldSystemDNS := systemDnsForRealDomainProbe
	oldResolver := resolveIp46ForRealDomainProbe
	defer func() {
		realDomainProbeTimeout = oldTimeout
		systemDnsForRealDomainProbe = oldSystemDNS
		resolveIp46ForRealDomainProbe = oldResolver
	}()

	realDomainProbeTimeout = 200 * time.Millisecond
	systemDnsForRealDomainProbe = func() (netip.AddrPort, error) {
		return netip.MustParseAddrPort("1.1.1.1:53"), nil
	}

	resolveIp46ForRealDomainProbe = func(ctx context.Context, dialer netproxy.Dialer, dns netip.AddrPort, host string, network string, race bool) (*netutils.Ip46, error, error) {
		return &netutils.Ip46{Ip4: netip.MustParseAddr("93.184.216.34")}, nil, nil
	}

	cp := newTestControlPlaneForRealDomainProbe()
	cp.dialMode = consts.DialMode_Domain
	cp.dnsController = &DnsController{dnsCache: sync.Map{}}

	dst := netip.MustParseAddrPort("8.8.8.8:443")
	_, reroute1, _ := cp.ChooseDialTarget(consts.OutboundUserDefinedMin, dst, "youtube.com")
	if reroute1 {
		t.Fatal("first unknown domain request should not reroute before warm-up")
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if known, real := cp.lookupRealDomainCache("youtube.com"); known && real {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if known, real := cp.lookupRealDomainCache("youtube.com"); !known || !real {
		t.Fatal("expected async warm-up to populate positive real-domain cache")
	}

	_, reroute2, _ := cp.ChooseDialTarget(consts.OutboundUserDefinedMin, dst, "youtube.com")
	if !reroute2 {
		t.Fatal("expected reroute after warm-up cache hit")
	}
}
