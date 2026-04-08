/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package dns

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/common/netutils"
)

func TestUpstreamResolverConcurrentCallsCacheSuccessfulInitialization(t *testing.T) {
	original := newUpstreamFunc
	t.Cleanup(func() {
		newUpstreamFunc = original
	})

	var initCalls atomic.Int32
	newUpstreamFunc = func(_ context.Context, raw *url.URL, _ string, _ resolveUpstreamIp46Func) (*Upstream, error) {
		initCalls.Add(1)
		return &Upstream{
			Scheme:   UpstreamScheme_UDP,
			Hostname: raw.Hostname(),
			Port:     53,
		}, nil
	}

	resolver := &UpstreamResolver{
		Raw:     mustParseURL("udp://8.8.8.8:53"),
		Network: "udp",
	}

	var wg sync.WaitGroup
	results := make(chan *Upstream, 8)
	for range 8 {
		wg.Go(func() {
			upstream, err := resolver.GetUpstream()
			if err != nil {
				t.Errorf("GetUpstream() error = %v", err)
				return
			}
			results <- upstream
		})
	}
	wg.Wait()
	close(results)

	if got := initCalls.Load(); got < 1 {
		t.Fatalf("expected initializer to be called at least once, got %d", got)
	}

	firstState := resolver.state.Load()
	if firstState == nil || firstState == &errorSentinel {
		t.Fatalf("expected successful cached state, got %#v", firstState)
	}
	firstUpstream := firstState.upstream
	if firstUpstream == nil {
		t.Fatalf("expected successful cached state, got %#v", firstState)
	}

	for upstream := range results {
		if upstream == nil {
			t.Fatal("expected concurrent initialization to return an upstream")
		}
		if upstream.Hostname != firstUpstream.Hostname || upstream.Port != firstUpstream.Port || upstream.Scheme != firstUpstream.Scheme {
			t.Fatalf("expected all goroutines to observe equivalent upstream values, got %#v want %#v", upstream, firstUpstream)
		}
	}

	upstream, err := resolver.GetUpstream()
	if err != nil {
		t.Fatalf("expected cached call to succeed: %v", err)
	}
	if upstream != firstUpstream {
		t.Fatal("expected cached call to reuse the stored upstream pointer")
	}
}

func TestUpstreamResolverRetriesAfterInitializerFailure(t *testing.T) {
	original := newUpstreamFunc
	t.Cleanup(func() {
		newUpstreamFunc = original
	})

	var initCalls atomic.Int32
	failErr := errors.New("transient failure")
	newUpstreamFunc = func(_ context.Context, raw *url.URL, _ string, _ resolveUpstreamIp46Func) (*Upstream, error) {
		call := initCalls.Add(1)
		if call == 1 {
			return nil, failErr
		}
		return &Upstream{
			Scheme:   UpstreamScheme_UDP,
			Hostname: raw.Hostname(),
			Port:     53,
		}, nil
	}

	resolver := &UpstreamResolver{
		Raw:     mustParseURL("udp://1.1.1.1:53"),
		Network: "udp",
	}

	if _, err := resolver.GetUpstream(); !errors.Is(err, failErr) {
		t.Fatalf("expected first call to fail with %v, got %v", failErr, err)
	}
	if state := resolver.state.Load(); state != &errorSentinel {
		t.Fatalf("expected error sentinel after failed init, got %#v", state)
	}

	upstream, err := resolver.GetUpstream()
	if err != nil {
		t.Fatalf("expected retry to succeed: %v", err)
	}
	if upstream == nil {
		t.Fatal("expected retry to return an upstream")
	}
	if got := initCalls.Load(); got != 2 {
		t.Fatalf("expected exactly two initializer calls, got %d", got)
	}
}

func TestUpstreamResolverRetriesAfterFinishCallbackFailure(t *testing.T) {
	original := newUpstreamFunc
	t.Cleanup(func() {
		newUpstreamFunc = original
	})

	var initCalls atomic.Int32
	newUpstreamFunc = func(_ context.Context, raw *url.URL, _ string, _ resolveUpstreamIp46Func) (*Upstream, error) {
		initCalls.Add(1)
		return &Upstream{
			Scheme:   UpstreamScheme_UDP,
			Hostname: raw.Hostname(),
			Port:     53,
		}, nil
	}

	failErr := errors.New("callback rejected upstream")
	var callbackCalls atomic.Int32
	resolver := &UpstreamResolver{
		Raw:     mustParseURL("udp://9.9.9.9:53"),
		Network: "udp",
		FinishInitCallback: func(_ *url.URL, _ *Upstream) error {
			if callbackCalls.Add(1) == 1 {
				return failErr
			}
			return nil
		},
	}

	if _, err := resolver.GetUpstream(); !errors.Is(err, failErr) {
		t.Fatalf("expected callback failure %v, got %v", failErr, err)
	}
	if state := resolver.state.Load(); state != &errorSentinel {
		t.Fatalf("expected error sentinel after callback failure, got %#v", state)
	}

	upstream, err := resolver.GetUpstream()
	if err != nil {
		t.Fatalf("expected retry after callback failure to succeed: %v", err)
	}
	if upstream == nil {
		t.Fatal("expected upstream after callback retry")
	}
	if got := callbackCalls.Load(); got != 2 {
		t.Fatalf("expected callback to be retried, got %d calls", got)
	}
	if got := initCalls.Load(); got != 2 {
		t.Fatalf("expected initializer to be retried, got %d calls", got)
	}
}

func TestCheckUpstreamsFormat_RequiresBootstrapResolverForNamedHost(t *testing.T) {
	s := &Dns{
		upstream: []*UpstreamResolver{
			{
				Raw:     mustParseURL("udp://dns.google:53"),
				Network: "udp",
			},
		},
	}

	err := s.CheckUpstreamsFormat()
	if err == nil {
		t.Fatal("expected named upstream without bootstrap resolver to be rejected")
	}
	if !strings.Contains(err.Error(), "bootstrap_resolver") {
		t.Fatalf("expected bootstrap_resolver guidance, got %v", err)
	}
}

func TestNewUpstream_UsesExplicitBootstrapResolver(t *testing.T) {
	var calls atomic.Int32
	upstream, err := NewUpstream(context.Background(), mustParseURL("udp://dns.google:53"), "udp", func(_ context.Context, host string, network string) (*netutils.Ip46, error, error) {
		calls.Add(1)
		if host != "dns.google" {
			t.Fatalf("unexpected host %q", host)
		}
		if network != "udp" {
			t.Fatalf("unexpected network %q", network)
		}
		return &netutils.Ip46{
			Ip4: netip.MustParseAddr("8.8.8.8"),
			Ip6: netip.MustParseAddr("2001:4860:4860::8888"),
		}, nil, nil
	})
	if err != nil {
		t.Fatalf("NewUpstream() error = %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected explicit bootstrap resolver to be called once, got %d", got)
	}
	if upstream.Hostname != "dns.google" {
		t.Fatalf("unexpected upstream hostname %q", upstream.Hostname)
	}
	if !upstream.Ip4.IsValid() || !upstream.Ip6.IsValid() {
		t.Fatalf("expected bootstrap resolver to populate both families, got %+v", upstream.Ip46)
	}
}

func TestNewUpstream_IPHostDoesNotRequireBootstrapResolver(t *testing.T) {
	upstream, err := NewUpstream(context.Background(), mustParseURL("udp://1.1.1.1:53"), "udp", func(_ context.Context, _ string, _ string) (*netutils.Ip46, error, error) {
		t.Fatal("bootstrap resolver should not be used for IP upstreams")
		return nil, nil, nil
	})
	if err != nil {
		t.Fatalf("NewUpstream() error = %v", err)
	}
	if upstream.Hostname != "1.1.1.1" {
		t.Fatalf("unexpected upstream hostname %q", upstream.Hostname)
	}
	if upstream.Ip4 != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("unexpected upstream IPv4 %v", upstream.Ip4)
	}
}

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
