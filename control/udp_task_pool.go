/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	// UdpTaskQueueLength is the buffer size for each per-flow UDP task queue.
	// QUIC sniff needs at most 3-5 ordered Initial packets; 128 is deliberately
	// chosen as a safe ceiling that is still 25× larger than the typical sniff
	// window but reduces per-flow channel allocation by 32× vs the old 4096.
	UdpTaskQueueLength = 128
)

var (
	// UdpTaskPoolAgingTime is the idle timeout before a queue is garbage collected.
	// Active flows continuously reset the timer with each packet.
	// 100ms is sufficient for burst traffic while enabling fast memory reclamation.
	UdpTaskPoolAgingTime = 100 * time.Millisecond
)

type UdpTask = func()

// UdpTaskQueue makes sure packets with the same UDP flow key are sent in order.
// Field order optimized for memory alignment (Go best practice).
type UdpTaskQueue struct {
	// 8-byte aligned fields first
	p         *UdpTaskPool
	ch        chan UdpTask
	wake      chan struct{}
	overflow  []UdpTask
	enqueueMu sync.Mutex

	// 8-byte fields
	agingTime time.Duration

	// 4-byte fields with padding
	refs atomic.Int32

	// 1-byte fields
	overflowLen  atomic.Int32 // track overflow length for lock-free idle check
	overflowMode bool

	key UdpFlowKey
}

func (q *UdpTaskQueue) notifyWake() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *UdpTaskQueue) enqueue(task UdpTask) {
	q.enqueueMu.Lock()
	defer q.enqueueMu.Unlock()

	if q.overflowMode {
		q.overflow = append(q.overflow, task)
		q.overflowLen.Store(int32(len(q.overflow)))
		q.notifyWake()
		return
	}

	select {
	case q.ch <- task:
		return
	default:
		// Hot-key degradation protection:
		// when the per-key channel is saturated, switch this key into
		// overflow mode so EmitTask stays non-blocking.
		// convoy() drains channel first and then overflow FIFO, preserving
		// in-order execution for this key.
		q.overflowMode = true
		q.overflow = append(q.overflow, task)
		q.overflowLen.Store(int32(len(q.overflow)))
		q.notifyWake()
	}
}

func (q *UdpTaskQueue) popOverflowTask() (UdpTask, bool) {
	q.enqueueMu.Lock()
	defer q.enqueueMu.Unlock()

	if len(q.overflow) == 0 {
		q.overflowMode = false
		return nil, false
	}
	task := q.overflow[0]
	q.overflow[0] = nil
	q.overflow = q.overflow[1:]
	if len(q.overflow) == 0 {
		q.overflowMode = false
		q.overflowLen.Store(0)
		// Keep a small preallocated slice to reduce allocations for bursty traffic
		if cap(q.overflow) > UdpTaskQueueLength*2 {
			q.overflow = make([]UdpTask, 0, UdpTaskQueueLength/4)
		} else {
			q.overflow = q.overflow[:0]
		}
	} else {
		q.overflowLen.Store(int32(len(q.overflow)))
		if len(q.overflow) > 0 && len(q.overflow) < cap(q.overflow)/4 && cap(q.overflow) > UdpTaskQueueLength {
			// Slice Drift Memory Leak prevention: shrink active capacity.
			shrunk := make([]UdpTask, len(q.overflow))
			copy(shrunk, q.overflow)
			q.overflow = shrunk
		}
	}
	return task, true
}

func (q *UdpTaskQueue) popReadyTask() (UdpTask, bool) {
	select {
	case task := <-q.ch:
		return task, true
	default:
	}
	return q.popOverflowTask()
}

// safeTimerReset resets the timer following Go best practice.
// Per Go documentation: "To reuse a Timer, call Reset and drain the channel
// if it fired." This ensures no stale timer event interferes with the next cycle.
func (q *UdpTaskQueue) safeTimerReset(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(q.agingTime)
}

func (q *UdpTaskQueue) executeTask(task UdpTask, timer *time.Timer) {
	task()
	q.safeTimerReset(timer)
}

func (q *UdpTaskQueue) convoy() {
	timer := time.NewTimer(q.agingTime)
	defer timer.Stop()

	for {
		if task, ok := q.popReadyTask(); ok {
			q.executeTask(task, timer)
			continue
		}

		select {
		case task := <-q.ch:
			q.executeTask(task, timer)
		case <-q.wake:
		case <-timer.C:
			// Idle GC: only remove queue when no in-flight EmitTask and no pending tasks.
			// Use atomic checks first to avoid lock contention.
			if q.refs.Load() > 0 || len(q.ch) > 0 || q.overflowLen.Load() > 0 {
				q.safeTimerReset(timer)
				continue
			}

			// CAS refs to lock out new acquireQueue and avoid time.Sleep
			if !q.refs.CompareAndSwap(0, -1000000) {
				q.safeTimerReset(timer)
				continue
			}

			// Try to delete from pool using CAS-like semantics via sync.Map
			if q.p.tryDeleteQueue(q.key, q) {
				q.p.queueChPool.Put(q.ch)
				return
			}
			// Check if mapping still points to current queue.
			// If not, this convoy is stale and must exit to prevent goroutine leak.
			if v, ok := q.p.queues.Load(q.key); !ok || v.(*UdpTaskQueue) != q {
				q.p.queueChPool.Put(q.ch)
				return
			}

			// Restore refs to 0 if deletion failed
			q.refs.Store(0)
			q.safeTimerReset(timer)
		}
	}
}

type UdpTaskPool struct {
	queueChPool sync.Pool
	queues      sync.Map // map[UdpFlowKey]*UdpTaskQueue
}

func NewUdpTaskPool() *UdpTaskPool {
	return &UdpTaskPool{
		queueChPool: sync.Pool{New: func() any {
			return make(chan UdpTask, UdpTaskQueueLength)
		}},
	}
}

// EmitTask makes sure packets with the same UDP flow key are sent in order.
func (p *UdpTaskPool) EmitTask(key UdpFlowKey, task UdpTask) {
	q := p.acquireQueue(key)
	q.enqueue(task)
	q.refs.Add(-1)
}

func (p *UdpTaskPool) acquireQueue(key UdpFlowKey) *UdpTaskQueue {
	// Fast path: check if queue exists without any lock contention
	if v, ok := p.queues.Load(key); ok {
		q := v.(*UdpTaskQueue)
		for {
			refs := q.refs.Load()
			if refs < 0 {
				goto createNew
			}
			if q.refs.CompareAndSwap(refs, refs+1) {
				return q
			}
		}
	}

createNew:

	// Slow path: create new queue using LoadOrStore to avoid race condition
	ch := p.queueChPool.Get().(chan UdpTask)
	newQ := &UdpTaskQueue{
		key:       key,
		p:         p,
		ch:        ch,
		wake:      make(chan struct{}, 1),
		agingTime: UdpTaskPoolAgingTime,
	}

	// LoadOrStore ensures atomic create-or-get semantics without explicit locks
	actual, loaded := p.queues.LoadOrStore(key, newQ)
	if loaded {
		// Another goroutine created the queue first, put our channel back
		p.queueChPool.Put(ch)
		q := actual.(*UdpTaskQueue)
		for {
			refs := q.refs.Load()
			if refs < 0 {
				// Use CompareAndDelete to only delete if still the same draining queue
				p.queues.CompareAndDelete(key, q)
				goto createNew
			}
			if q.refs.CompareAndSwap(refs, refs+1) {
				return q
			}
		}
	}
	q := actual.(*UdpTaskQueue)
	q.refs.Add(1)

	// Only start the convoy goroutine for newly created queues
	if !loaded {
		go q.convoy()
	}

	return q
}

// tryDeleteQueue attempts to delete the queue if it's still the same instance.
// Returns true if deletion was successful, false otherwise.
// Uses CompareAndDelete for atomic CAS semantics (Go 1.20+ best practice).
func (p *UdpTaskPool) tryDeleteQueue(key UdpFlowKey, expected *UdpTaskQueue) bool {
	return p.queues.CompareAndDelete(key, expected)
}

var (
	DefaultUdpTaskPool = NewUdpTaskPool()
)
