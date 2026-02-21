/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUdpTaskPool_PreserveOrderPerKey(t *testing.T) {
	pool := NewUdpTaskPool()
	key := netip.MustParseAddrPort("127.0.0.1:10001")

	const n = 200
	got := make([]int, 0, n)
	var mu sync.Mutex
	var done atomic.Int32

	for i := 0; i < n; i++ {
		idx := i
		pool.EmitTask(key, func() {
			mu.Lock()
			got = append(got, idx)
			mu.Unlock()
			done.Add(1)
		})
	}

	require.Eventually(t, func() bool { return done.Load() == n }, 2*time.Second, 10*time.Millisecond)

	require.Len(t, got, n)
	for i := 0; i < n; i++ {
		require.Equal(t, i, got[i])
	}
}

func TestUdpTaskPool_ConcurrentDifferentKeys(t *testing.T) {
	pool := NewUdpTaskPool()
	var active atomic.Int32
	var peak atomic.Int32
	var done atomic.Int32

	const tasks = 40

	for i := 0; i < tasks; i++ {
		key := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(11000+i%8))
		pool.EmitTask(key, func() {
			cur := active.Add(1)
			for {
				old := peak.Load()
				if cur <= old || peak.CompareAndSwap(old, cur) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			active.Add(-1)
			done.Add(1)
		})
	}

	require.Eventually(t, func() bool { return done.Load() == tasks }, 3*time.Second, 10*time.Millisecond)

	require.GreaterOrEqual(t, peak.Load(), int32(2), "different keys should run concurrently")
}

func TestUdpTaskPool_RecreateQueueAfterIdle(t *testing.T) {
	oldTimeout := DefaultNatTimeout
	DefaultNatTimeout = 30 * time.Millisecond
	defer func() { DefaultNatTimeout = oldTimeout }()

	pool := NewUdpTaskPool()
	key := netip.MustParseAddrPort("127.0.0.1:10002")

	var count atomic.Int32
	pool.EmitTask(key, func() { count.Add(1) })
	require.Eventually(t, func() bool { return count.Load() == 1 }, time.Second, 5*time.Millisecond)

	// Wait for idle GC and re-emit task. It should still be executed successfully.
	time.Sleep(2 * DefaultNatTimeout)
	pool.EmitTask(key, func() { count.Add(1) })
	require.Eventually(t, func() bool { return count.Load() == 2 }, time.Second, 5*time.Millisecond)
}

func TestUdpTaskPool_HotKeyOverflow_NonBlockingAndOrdered(t *testing.T) {
	pool := NewUdpTaskPool()
	key := netip.MustParseAddrPort("127.0.0.1:19001")

	started := make(chan struct{})
	release := make(chan struct{})

	pool.EmitTask(key, func() {
		close(started)
		<-release
	})

	require.Eventually(t, func() bool {
		select {
		case <-started:
			return true
		default:
			return false
		}
	}, time.Second, 5*time.Millisecond)

	const n = UdpTaskQueueLength + 64
	got := make([]int, 0, n)
	var (
		mu   sync.Mutex
		done atomic.Int32
	)

	enqueued := make(chan struct{})
	go func() {
		for i := 0; i < n; i++ {
			idx := i
			pool.EmitTask(key, func() {
				mu.Lock()
				got = append(got, idx)
				mu.Unlock()
				done.Add(1)
			})
		}
		close(enqueued)
	}()

	select {
	case <-enqueued:
		// enqueue path should not block even when per-key channel is saturated.
	case <-time.After(200 * time.Millisecond):
		t.Fatal("EmitTask blocked on hot key saturation")
	}

	close(release)
	require.Eventually(t, func() bool { return done.Load() == n }, 3*time.Second, 10*time.Millisecond)

	require.Len(t, got, n)
	for i := 0; i < n; i++ {
		require.Equal(t, i, got[i])
	}
}
