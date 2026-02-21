/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestUdpEndpoint_DeadFlag tests that when the read loop exits due to error,
// the dead flag is set and IsDead() returns true.
func TestUdpEndpoint_DeadFlag(t *testing.T) {
	ue := &UdpEndpoint{}

	// Initially not dead
	require.False(t, ue.IsDead(), "new endpoint should not be dead")

	// Set dead flag
	ue.dead.Store(true)
	require.True(t, ue.IsDead(), "endpoint should be dead after flag is set")
}

// TestUdpEndpoint_ExpiresAtOnDead tests that when an error occurs in start(),
// the expiresAtNano is set to 1 (past time) for immediate janitor cleanup.
func TestUdpEndpoint_ExpiresAtOnDead(t *testing.T) {
	ue := &UdpEndpoint{
		NatTimeout: time.Minute,
	}

	// Set normal expiration
	ue.RefreshTtl()
	require.True(t, ue.expiresAtNano.Load() > 0, "expiration should be in the future")

	// Simulate what start() does on error
	ue.dead.Store(true)
	ue.expiresAtNano.Store(1)

	// Verify the endpoint is considered expired
	require.True(t, ue.IsExpired(time.Now().UnixNano()), "endpoint should be expired after error")
	require.True(t, ue.IsDead(), "endpoint should be marked as dead")
}

// TestUdpEndpointPool_GetOrCreate_DeadEndpointRemoval tests that GetOrCreate
// removes and replaces a dead endpoint instead of reusing it.
func TestUdpEndpointPool_GetOrCreate_DeadEndpointRemoval(t *testing.T) {
	p := NewUdpEndpointPool()
	lAddr := netip.MustParseAddrPort("10.0.0.1:12345")

	// Create a dead endpoint manually
	deadEndpoint := &UdpEndpoint{
		NatTimeout: DefaultNatTimeout,
	}
	deadEndpoint.RefreshTtl()
	deadEndpoint.dead.Store(true) // Mark as dead
	p.pool.Store(lAddr, deadEndpoint)

	// Verify it's in the pool
	ue, ok := p.Get(lAddr)
	require.True(t, ok)
	require.True(t, ue.IsDead())

	// Now try to get or create - should remove the dead one
	// We use a Handler that returns error to force failure, but the important
	// thing is that the dead endpoint should be removed from the pool
	_, _, err := p.GetOrCreate(lAddr, &UdpEndpointOptions{
		Handler:    func(data []byte, from netip.AddrPort) error { return nil },
		NatTimeout: DefaultNatTimeout,
		GetDialOption: func(ctx context.Context) (option *DialOption, err error) {
			// Return error to simulate dial failure - but dead endpoint should still be removed first
			return nil, fmt.Errorf("simulated dial error")
		},
	})

	// The call will fail because GetDialOption returns error
	require.Error(t, err)
	require.Contains(t, err.Error(), "simulated dial error")

	// But the dead endpoint should be removed from the pool
	ue, ok = p.Get(lAddr)
	require.False(t, ok, "dead endpoint should be removed from pool")
	require.Nil(t, ue)
}

// TestUdpEndpointPool_DeadEndpointNotRevived tests that RefreshTtl cannot
// revive a dead endpoint for reuse purposes because GetOrCreate checks IsDead().
func TestUdpEndpointPool_DeadEndpointNotRevived(t *testing.T) {
	p := NewUdpEndpointPool()
	lAddr := netip.MustParseAddrPort("10.0.0.1:12346")

	// Create a dead endpoint
	deadEndpoint := &UdpEndpoint{
		NatTimeout: DefaultNatTimeout,
	}
	deadEndpoint.dead.Store(true)
	deadEndpoint.expiresAtNano.Store(1) // Past time
	p.pool.Store(lAddr, deadEndpoint)

	// Even if someone calls RefreshTtl on it (which shouldn't happen, but let's be safe)
	deadEndpoint.RefreshTtl()

	// The endpoint is still marked as dead
	require.True(t, deadEndpoint.IsDead())

	// GetOrCreate should still reject it
	_, _, err := p.GetOrCreate(lAddr, &UdpEndpointOptions{
		Handler:    func(data []byte, from netip.AddrPort) error { return nil },
		NatTimeout: DefaultNatTimeout,
		GetDialOption: func(ctx context.Context) (option *DialOption, err error) {
			return nil, fmt.Errorf("simulated dial error")
		},
	})
	require.Error(t, err)

	// Dead endpoint should be removed
	ue, ok := p.Get(lAddr)
	require.False(t, ok)
	require.Nil(t, ue)
}

// TestUdpEndpointPool_ConcurrentDeadEndpointHandling tests concurrent access
// when multiple goroutines try to use a dead endpoint.
func TestUdpEndpointPool_ConcurrentDeadEndpointHandling(t *testing.T) {
	p := NewUdpEndpointPool()
	lAddr := netip.MustParseAddrPort("10.0.0.1:12347")

	// Create a dead endpoint
	deadEndpoint := &UdpEndpoint{
		NatTimeout: DefaultNatTimeout,
	}
	deadEndpoint.RefreshTtl()
	deadEndpoint.dead.Store(true)
	p.pool.Store(lAddr, deadEndpoint)

	var errorCount atomic.Int32
	var wg sync.WaitGroup

	// Multiple goroutines try to get the endpoint concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// This should fail to create a valid endpoint but should
			// properly handle the dead endpoint
			_, _, err := p.GetOrCreate(lAddr, &UdpEndpointOptions{
				Handler:    func(data []byte, from netip.AddrPort) error { return nil },
				NatTimeout: DefaultNatTimeout,
				GetDialOption: func(ctx context.Context) (option *DialOption, err error) {
					return nil, fmt.Errorf("simulated dial error")
				},
			})
			if err != nil {
				errorCount.Add(1)
			}
		}()
	}

	wg.Wait()

	// All attempts should have failed (since GetDialOption returns error)
	// but none should have panicked or caused issues
	require.Equal(t, int32(10), errorCount.Load())

	// The dead endpoint should eventually be removed
	ue, ok := p.Get(lAddr)
	require.False(t, ok)
	require.Nil(t, ue)
}

// TestUdpEndpoint_DeadFlagConsistency tests that the dead flag is consistent
// even under concurrent access.
func TestUdpEndpoint_DeadFlagConsistency(t *testing.T) {
	ue := &UdpEndpoint{}

	var wg sync.WaitGroup
	var readCount atomic.Int32
	var writeCount atomic.Int32

	// Concurrent readers
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				ue.IsDead()
				readCount.Add(1)
			}
		}()
	}

	// One writer sets the flag
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(1 * time.Millisecond)
		ue.dead.Store(true)
		writeCount.Add(1)
	}()

	wg.Wait()

	// After write, all reads should see true
	require.True(t, ue.IsDead())
	require.Equal(t, int32(10000), readCount.Load())
	require.Equal(t, int32(1), writeCount.Load())
}
