/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUdpTaskPool_PreserveOrderPerKey(t *testing.T) {
	pool := NewUdpTaskPool()

	const n = 200
	got := make([]int, 0, n)
	var mu sync.Mutex
	var done atomic.Int32

	for i := 0; i < n; i++ {
		idx := i
		pool.EmitTask("same-key", func() {
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
		key := "k" + string(rune('a'+(i%8)))
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

	var count atomic.Int32
	pool.EmitTask("idle-key", func() { count.Add(1) })
	require.Eventually(t, func() bool { return count.Load() == 1 }, time.Second, 5*time.Millisecond)

	// Wait for idle GC and re-emit task. It should still be executed successfully.
	time.Sleep(2 * DefaultNatTimeout)
	pool.EmitTask("idle-key", func() { count.Add(1) })
	require.Eventually(t, func() bool { return count.Load() == 2 }, time.Second, 5*time.Millisecond)
}
