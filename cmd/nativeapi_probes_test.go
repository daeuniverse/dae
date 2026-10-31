/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"errors"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
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
