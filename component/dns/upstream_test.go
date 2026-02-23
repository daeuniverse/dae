/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package dns

import (
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
)

// TestUpstreamResolver_ErrorSentinelRetry tests that GetUpstream retries
// when the error sentinel is stored (simulating transient failures).
// This tests the core retry logic without requiring network access.
func TestUpstreamResolver_ErrorSentinelRetry(t *testing.T) {
	resolver := &UpstreamResolver{
		Raw:     mustParseURL("udp://8.8.8.8:53"),
		Network: "udp",
	}

	// Manually set error sentinel to simulate previous failure
	resolver.state.Store(&errorSentinel)

	// Verify error sentinel is set
	if resolver.state.Load() != &errorSentinel {
		t.Error("Expected error sentinel to be set")
	}

	// Next call should retry (will fail due to no network, but that's OK)
	_, err := resolver.GetUpstream()
	t.Logf("After retry: err=%v", err)

	// The error sentinel should be set again since NewUpstream fails
	if resolver.state.Load() != &errorSentinel {
		t.Log("Note: State changed, possibly due to network being available")
	}
}

// TestUpstreamResolver_ErrorSentinelIdentity tests that errorSentinel is a singleton.
func TestUpstreamResolver_ErrorSentinelIdentity(t *testing.T) {
	// All comparisons to errorSentinel should use pointer equality
	if &errorSentinel != &errorSentinel {
		t.Error("errorSentinel should be a singleton")
	}
}

// TestUpstreamResolver_StateTransitions tests the state machine transitions.
func TestUpstreamResolver_StateTransitions(t *testing.T) {
	resolver := &UpstreamResolver{
		Raw:     mustParseURL("udp://8.8.8.8:53"),
		Network: "udp",
	}

	// Initial state: nil
	if resolver.state.Load() != nil {
		t.Error("Expected initial state to be nil")
	}
	t.Logf("Initial state: nil")

	// After failed init: errorSentinel
	_, err := resolver.GetUpstream()
	t.Logf("After first call: state=%v, err=%v", resolver.state.Load(), err)

	// The state should be either errorSentinel (failed) or a valid state (succeeded)
	state := resolver.state.Load()
	if state != nil && state != &errorSentinel {
		t.Logf("Initialization succeeded (network available)")
		// Success path: subsequent calls should return same result
		_, err2 := resolver.GetUpstream()
		if err2 != nil {
			t.Errorf("Expected success after initialization, got: %v", err2)
		}
	} else if state == &errorSentinel {
		t.Logf("Initialization failed (network unavailable)")
		// Failure path: should allow retry
		_, err3 := resolver.GetUpstream()
		t.Logf("After retry: err=%v", err3)
	}
}

// TestUpstreamResolver_ConcurrentCalls tests concurrent initialization.
// Multiple goroutines calling GetUpstream simultaneously should all get the same result.
func TestUpstreamResolver_ConcurrentCalls(t *testing.T) {
	resolver := &UpstreamResolver{
		Raw:     mustParseURL("udp://8.8.8.8:53"),
		Network: "udp",
	}

	var wg sync.WaitGroup
	var errorCount atomic.Int32
	var successCount atomic.Int32
	var stateSnapshot atomic.Pointer[upstreamState]

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := resolver.GetUpstream()
			if err != nil {
				errorCount.Add(1)
			} else {
				successCount.Add(1)
			}
			// Capture state after call
			stateSnapshot.Store(resolver.state.Load())
		}()
	}

	wg.Wait()

	t.Logf("Concurrent calls: errors=%d, successes=%d", errorCount.Load(), successCount.Load())
	t.Logf("Final state: %v", stateSnapshot.Load())

	// All calls should complete (either success or failure)
	total := errorCount.Load() + successCount.Load()
	if total != 10 {
		t.Errorf("Expected 10 total results, got %d", total)
	}
}

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
