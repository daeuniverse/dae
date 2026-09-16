/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
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

// The UDP task pool is the single ordered ingress path. These tests pin the
// properties that were lost when the dispatcher behavioural suite was pruned:
// per-flow FIFO across the channel-to-overflow transition, cross-flow
// independence, panic isolation inside a convoy, and closed-pool rejection.

// orderRecorder captures per-flow execution order under a mutex.
type orderRecorder struct {
	mu   sync.Mutex
	seen []int
}

func (r *orderRecorder) record(index int) {
	r.mu.Lock()
	r.seen = append(r.seen, index)
	r.mu.Unlock()
}

func (r *orderRecorder) snapshot() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int(nil), r.seen...)
}

// waitForCount blocks until the recorder has observed want entries.
func (r *orderRecorder) waitForCount(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		got := len(r.seen)
		r.mu.Unlock()
		if got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("recorded %d of %d tasks before timeout", got, want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func udpTaskPoolTestKey() UdpFlowKey {
	return NewUdpFlowKey(
		netip.MustParseAddrPort("198.51.100.10:40000"),
		netip.MustParseAddrPort("203.0.113.1:27015"),
	)
}

func udpTaskPoolSecondTestKey() UdpFlowKey {
	return NewUdpFlowKey(
		netip.MustParseAddrPort("198.51.100.11:40001"),
		netip.MustParseAddrPort("203.0.113.2:27016"),
	)
}

// TestUdpTaskPoolPreservesPerFlowOrderAcrossOverflow submits more tasks than
// one queue's channel capacity so the queue degrades into overflow mode, then
// asserts submission order equals execution order for the flow.
func TestUdpTaskPoolPreservesPerFlowOrderAcrossOverflow(t *testing.T) {
	pool := NewUdpTaskPool()
	t.Cleanup(func() { pool.Close() })

	key := udpTaskPoolTestKey()
	recorder := &orderRecorder{}
	total := UdpTaskQueueLength + 64

	for i := range total {
		index := i
		require.True(t, pool.EmitTask(key, udpTaskFunc(func() {
			recorder.record(index)
		})), "EmitTask rejected task %d below any capacity limit", i)
	}

	recorder.waitForCount(t, total)
	got := recorder.snapshot()
	require.Len(t, got, total)
	for i := range total {
		require.Equal(t, i, got[i], "task %d executed out of order", i)
	}
}

// TestUdpTaskPoolKeepsFlowsIndependent interleaves submissions across two
// flows and asserts each flow preserves its own FIFO.
func TestUdpTaskPoolKeepsFlowsIndependent(t *testing.T) {
	pool := NewUdpTaskPool()
	t.Cleanup(func() { pool.Close() })

	first := &orderRecorder{}
	second := &orderRecorder{}
	total := UdpTaskQueueLength + 32

	for i := range total {
		index := i
		require.True(t, pool.EmitTask(udpTaskPoolTestKey(), udpTaskFunc(func() {
			first.record(index)
		})))
		require.True(t, pool.EmitTask(udpTaskPoolSecondTestKey(), udpTaskFunc(func() {
			second.record(index)
		})))
	}

	first.waitForCount(t, total)
	second.waitForCount(t, total)
	for i := range total {
		require.Equal(t, i, first.snapshot()[i], "first flow task %d out of order", i)
		require.Equal(t, i, second.snapshot()[i], "second flow task %d out of order", i)
	}
}

// TestUdpTaskPoolPanicDoesNotKillConvoy verifies the per-task panic isolation:
// a panicking task is reported and skipped while the convoy keeps executing
// the remaining tasks of the flow in order.
func TestUdpTaskPoolPanicDoesNotKillConvoy(t *testing.T) {
	pool := NewUdpTaskPool()
	t.Cleanup(func() { pool.Close() })

	key := udpTaskPoolTestKey()
	recorder := &orderRecorder{}
	total := 16

	for i := range total {
		index := i
		require.True(t, pool.EmitTask(key, udpTaskFunc(func() {
			if index == 5 {
				panic("boom: poisoned task")
			}
			recorder.record(index)
		})))
	}

	recorder.waitForCount(t, total-1)
	got := recorder.snapshot()
	want := make([]int, 0, total-1)
	for i := range total {
		if i != 5 {
			want = append(want, i)
		}
	}
	require.Equal(t, want, got)
}

// TestUdpTaskPoolConcurrentSubmitAndClose hammers the pool from several
// producers while it closes. The contract is termination without deadlock or
// panic; after Close returns, new submissions must be rejected.
func TestUdpTaskPoolConcurrentSubmitAndClose(t *testing.T) {
	pool := NewUdpTaskPool()

	const producers = 8
	perProducer := UdpTaskQueueLength
	var executed atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range producers {
		wg.Go(func() {
			<-start
			for range perProducer {
				if !pool.EmitTask(udpTaskPoolTestKey(), udpTaskFunc(func() {
					executed.Add(1)
				})) {
					return
				}
			}
		})
	}
	close(start)
	time.Sleep(5 * time.Millisecond)
	pool.Close()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("producers did not settle after Close")
	}

	require.False(t, pool.EmitTask(udpTaskPoolTestKey(), udpTaskFunc(func() {})),
		"EmitTask accepted work after Close")
}

type ownedUdpTask struct {
	runs     *atomic.Int32
	discards *atomic.Int32
	started  chan struct{}
	release  <-chan struct{}
}

func (t *ownedUdpTask) Run() {
	t.runs.Add(1)
	if t.started != nil {
		close(t.started)
	}
	if t.release != nil {
		<-t.release
	}
}

func (t *ownedUdpTask) Discard() { t.discards.Add(1) }

type blockingDiscardUdpTask struct {
	started chan struct{}
	release <-chan struct{}
}

func (*blockingDiscardUdpTask) Run() {}

func (t *blockingDiscardUdpTask) Discard() {
	close(t.started)
	<-t.release
}

func TestUdpTaskPoolCloseWaitsForAlreadyRetiringConvoy(t *testing.T) {
	pool := NewUdpTaskPool()
	release := make(chan struct{})
	started := make(chan struct{})
	queue := &UdpTaskQueue{
		p: pool, ch: make(chan UdpTask, 1), wake: make(chan struct{}, 1),
		done: make(chan struct{}),
	}
	queue.refs.Store(-1000000)
	queue.ch <- &blockingDiscardUdpTask{started: started, release: release}
	pool.convoys.Add(1)
	go queue.convoy()
	<-started

	closed := make(chan struct{})
	go func() {
		pool.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close did not wait for the already-retiring convoy")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after retiring convoy cleanup")
	}
}

func TestUdpTaskPoolBoundsHotFlowAndDiscardsExactlyOnce(t *testing.T) {
	pool := NewUdpTaskPool()
	key := udpTaskPoolTestKey()
	started := make(chan struct{})
	release := make(chan struct{})
	var blockerRuns atomic.Int32
	var blockerDiscards atomic.Int32
	require.True(t, pool.EmitTask(key, &ownedUdpTask{
		runs: &blockerRuns, discards: &blockerDiscards,
		started: started, release: release,
	}))
	<-started

	accepted := make([]*ownedUdpTask, 0, UdpTaskQueueLength+UdpTaskQueueMaxOverflow)
	for range UdpTaskQueueLength + UdpTaskQueueMaxOverflow {
		task := &ownedUdpTask{runs: new(atomic.Int32), discards: new(atomic.Int32)}
		require.True(t, pool.EmitTask(key, task))
		accepted = append(accepted, task)
	}
	rejected := &ownedUdpTask{runs: new(atomic.Int32), discards: new(atomic.Int32)}
	require.False(t, pool.EmitTask(key, rejected))
	discardTask(rejected)
	require.Equal(t, uint64(1), pool.DroppedTasks())

	value, ok := pool.queues.Load(key)
	require.True(t, ok)
	queue := value.(*UdpTaskQueue)
	closed := make(chan struct{})
	go func() {
		pool.Close()
		close(closed)
	}()
	require.Eventually(t, func() bool {
		queue.enqueueMu.Lock()
		defer queue.enqueueMu.Unlock()
		return queue.closed
	}, time.Second, time.Millisecond)
	close(release)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not wait for convoy cleanup")
	}

	require.Equal(t, int32(1), blockerRuns.Load())
	require.Zero(t, blockerDiscards.Load())
	require.Zero(t, rejected.runs.Load())
	require.Equal(t, int32(1), rejected.discards.Load())
	for i, task := range accepted {
		require.Zero(t, task.runs.Load(), "queued task %d ran after Close", i)
		require.Equal(t, int32(1), task.discards.Load(), "queued task %d discard count", i)
	}
}
