/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package dns

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
)

func TestUpstreamResolverConcurrentCallsCacheSuccessfulInitialization(t *testing.T) {
	original := newUpstreamFunc
	t.Cleanup(func() {
		newUpstreamFunc = original
	})

	var initCalls atomic.Int32
	newUpstreamFunc = func(_ context.Context, raw *url.URL, _ string) (*Upstream, error) {
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
	if firstState == nil || firstState == &errorSentinel || firstState.upstream == nil {
		t.Fatalf("expected successful cached state, got %#v", firstState)
	}

	for upstream := range results {
		if upstream == nil {
			t.Fatal("expected concurrent initialization to return an upstream")
		}
		if upstream.Hostname != firstState.upstream.Hostname || upstream.Port != firstState.upstream.Port || upstream.Scheme != firstState.upstream.Scheme {
			t.Fatalf("expected all goroutines to observe equivalent upstream values, got %#v want %#v", upstream, firstState.upstream)
		}
	}

	upstream, err := resolver.GetUpstream()
	if err != nil {
		t.Fatalf("expected cached call to succeed: %v", err)
	}
	if upstream != firstState.upstream {
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
	newUpstreamFunc = func(_ context.Context, raw *url.URL, _ string) (*Upstream, error) {
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
	newUpstreamFunc = func(_ context.Context, raw *url.URL, _ string) (*Upstream, error) {
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

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
