/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const UdpTaskQueueLength = 128

type UdpTask = func()

// UdpTaskQueue make sure packets with the same key (4 tuples) will be sent in order.
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

	// 24-byte field (netip.AddrPort is struct{addr [16]byte, port uint16, zone string})
	key netip.AddrPort

	// 1-byte fields
	overflowLen  atomic.Int32 // track overflow length for lock-free idle check
	overflowMode bool
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
			// Try to delete from pool using CAS-like semantics via sync.Map
			if q.p.tryDeleteQueue(q.key, q) {
				q.p.queueChPool.Put(q.ch)
				return
			}
			q.safeTimerReset(timer)
		}
	}
}

type UdpTaskPool struct {
	queueChPool sync.Pool
	queues      sync.Map // map[netip.AddrPort]*UdpTaskQueue
}

func NewUdpTaskPool() *UdpTaskPool {
	return &UdpTaskPool{
		queueChPool: sync.Pool{New: func() any {
			return make(chan UdpTask, UdpTaskQueueLength)
		}},
	}
}

// EmitTask: Make sure packets with the same key (4 tuples) will be sent in order.
func (p *UdpTaskPool) EmitTask(key netip.AddrPort, task UdpTask) {
	q := p.acquireQueue(key)
	q.enqueue(task)
	q.refs.Add(-1)
}

func (p *UdpTaskPool) acquireQueue(key netip.AddrPort) *UdpTaskQueue {
	// Fast path: check if queue exists without any lock contention
	if v, ok := p.queues.Load(key); ok {
		q := v.(*UdpTaskQueue)
		q.refs.Add(1)
		return q
	}

	// Slow path: create new queue using LoadOrStore to avoid race condition
	ch := p.queueChPool.Get().(chan UdpTask)
	newQ := &UdpTaskQueue{
		key:       key,
		p:         p,
		ch:        ch,
		wake:      make(chan struct{}, 1),
		agingTime: DefaultNatTimeout,
	}

	// LoadOrStore ensures atomic create-or-get semantics without explicit locks
	actual, loaded := p.queues.LoadOrStore(key, newQ)
	if loaded {
		// Another goroutine created the queue first, put our channel back
		p.queueChPool.Put(ch)
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
func (p *UdpTaskPool) tryDeleteQueue(key netip.AddrPort, expected *UdpTaskQueue) bool {
	// Use Load+Delete with verification to avoid deleting a recreated queue
	if v, loaded := p.queues.LoadAndDelete(key); loaded {
		return v.(*UdpTaskQueue) == expected
	}
	return false
}

var (
	DefaultUdpTaskPool = NewUdpTaskPool()
)
