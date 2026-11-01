/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func apiErrorOf(t *testing.T, err error) *nativeapi.APIError {
	t.Helper()
	var apiErr *nativeapi.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *nativeapi.APIError", err)
	}
	return apiErr
}

func TestProbeGateBoundsQueue(t *testing.T) {
	gate := newProbeGate()
	now := time.Now()
	for i := 0; i < probeMaxActiveJobs+probeMaxQueuedJobs; i++ {
		if err := gate.reserve(now); err != nil {
			t.Fatalf("reserve %d: %v", i, err)
		}
	}
	apiErr := apiErrorOf(t, gate.reserve(now))
	if apiErr.Status != 503 || apiErr.RetryAfterSeconds != 1 {
		t.Fatalf("queue full error = %+v, want 503 with Retry-After 1", apiErr)
	}
}

func TestProbeGateRateLimitAndWindowReset(t *testing.T) {
	gate := newProbeGate()
	now := time.Now()
	gate.windowStart = now
	gate.windowCount = probeGlobalRequestsPerMin

	apiErr := apiErrorOf(t, gate.reserve(now))
	if apiErr.Status != 429 || apiErr.RetryAfterSeconds != probeRateLimitedRetryAfter {
		t.Fatalf("rate limit error = %+v, want 429 with Retry-After %d", apiErr, probeRateLimitedRetryAfter)
	}

	if err := gate.reserve(now.Add(probeRateLimitWindow)); err != nil {
		t.Fatalf("reserve after window reset: %v", err)
	}
	gate.mu.Lock()
	inFlight := gate.inFlight
	gate.mu.Unlock()
	if inFlight != 1 {
		t.Fatalf("inFlight = %d, want 1", inFlight)
	}
}

func TestProbeGateRunsAtMostActiveJobsConcurrently(t *testing.T) {
	gate := newProbeGate()
	release := make(chan struct{})
	running := make(chan struct{}, probeMaxActiveJobs)
	for i := 0; i < probeMaxActiveJobs; i++ {
		go gate.run(func() {
			running <- struct{}{}
			<-release
		})
	}
	for i := 0; i < probeMaxActiveJobs; i++ {
		select {
		case <-running:
		case <-time.After(2 * time.Second):
			t.Fatal("probe slot did not start")
		}
	}

	started := make(chan struct{})
	go gate.run(func() { close(started) })
	select {
	case <-started:
		t.Fatal("probe beyond max_active_jobs started while all slots were busy")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("queued probe never started after slots were released")
	}
}

func TestProbeNodeAddressUsesTheNodeServer(t *testing.T) {
	// tcp_connect has to reach the node's own server, not a public address
	// through the proxy: a reachable node whose exit cannot reach 1.1.1.1 used
	// to answer unavailable.
	d, err := dialer.NewFromLinkContext(context.Background(), &dialer.GlobalOption{Log: logrus.New()}, dialer.InstanceOption{DisableCheck: true}, "socks5://192.0.2.10:1080", "")
	if err != nil {
		t.Fatalf("build dialer: %v", err)
	}
	defer func() { _ = d.Close() }()
	if got := probeNodeAddress(d); got != "192.0.2.10:1080" {
		t.Fatalf("probeNodeAddress = %q, want the node server 192.0.2.10:1080", got)
	}
	// An outbound with no server address falls back to the well-known endpoint.
	if got := probeNodeAddress(nil); got != "" {
		t.Fatalf("probeNodeAddress(nil) = %q, want empty", got)
	}
	if got := probeDialAddress("tcp", "ipv4"); got != "1.1.1.1:443" {
		t.Fatalf("probeDialAddress(tcp, ipv4) = %q", got)
	}
	if got := probeDialAddress("udp", "ipv6"); got != "[2606:4700:4700::1111]:53" {
		t.Fatalf("probeDialAddress(udp, ipv6) = %q", got)
	}
}

func TestProbeRejectsUnknownKind(t *testing.T) {
	item := runProbeMember(context.Background(), probeMember{id: "n", dialer: nil}, nativeapi.ProbeRequest{Kind: "icmp"}, "tcp", 0, nil)
	if item.State != "unavailable" {
		t.Fatalf("state = %q, want unavailable", item.State)
	}
	if item.Error == nil || *item.Error != "dialer is unavailable" {
		t.Fatalf("error = %v", item.Error)
	}
}
