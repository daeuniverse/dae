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
const udpTaskPoolShardCount = 64

type UdpTask = func()

// UdpTaskQueue make sure packets with the same key (4 tuples) will be sent in order.
type UdpTaskQueue struct {
	key       netip.AddrPort
	p         *UdpTaskPool
	shard     *udpTaskShard
	ch        chan UdpTask
	wake      chan struct{}
	agingTime time.Duration
	refs      atomic.Int32

	enqueueMu    sync.Mutex
	overflow     []UdpTask
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
		if cap(q.overflow) > UdpTaskQueueLength*4 {
			q.overflow = nil
		} else {
			q.overflow = q.overflow[:0]
		}
	}
	return task, true
}

func (q *UdpTaskQueue) pendingOverflowLen() int {
	q.enqueueMu.Lock()
	defer q.enqueueMu.Unlock()
	return len(q.overflow)
}

func (q *UdpTaskQueue) popReadyTask() (UdpTask, bool) {
	select {
	case task := <-q.ch:
		return task, true
	default:
	}
	return q.popOverflowTask()
}

func (q *UdpTaskQueue) executeTask(task UdpTask, timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}

	task()
	timer.Reset(q.agingTime)
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
			q.shard.mu.Lock()
			current, ok := q.shard.m[q.key]
			if ok && current == q && q.refs.Load() == 0 && len(q.ch) == 0 && q.pendingOverflowLen() == 0 {
				delete(q.shard.m, q.key)
				q.shard.mu.Unlock()
				q.p.queueChPool.Put(q.ch)
				return
			}
			q.shard.mu.Unlock()
			timer.Reset(q.agingTime)
		}
	}
}

type udpTaskShard struct {
	mu sync.RWMutex
	m  map[netip.AddrPort]*UdpTaskQueue
}

type UdpTaskPool struct {
	queueChPool sync.Pool
	shards      []udpTaskShard
}

func NewUdpTaskPool() *UdpTaskPool {
	p := &UdpTaskPool{
		queueChPool: sync.Pool{New: func() any {
			return make(chan UdpTask, UdpTaskQueueLength)
		}},
		shards: make([]udpTaskShard, udpTaskPoolShardCount),
	}
	for i := range p.shards {
		p.shards[i].m = make(map[netip.AddrPort]*UdpTaskQueue)
	}
	return p
}

// EmitTask: Make sure packets with the same key (4 tuples) will be sent in order.
func (p *UdpTaskPool) EmitTask(key netip.AddrPort, task UdpTask) {
	q := p.acquireQueue(key)
	q.enqueue(task)
	q.refs.Add(-1)
}

func (p *UdpTaskPool) acquireQueue(key netip.AddrPort) *UdpTaskQueue {
	shard := p.shardFor(key)

	shard.mu.RLock()
	if q, ok := shard.m[key]; ok {
		q.refs.Add(1)
		shard.mu.RUnlock()
		return q
	}
	shard.mu.RUnlock()

	shard.mu.Lock()
	q, ok := shard.m[key]
	if !ok {
		ch := p.queueChPool.Get().(chan UdpTask)
		q = &UdpTaskQueue{
			key:       key,
			p:         p,
			shard:     shard,
			ch:        ch,
			wake:      make(chan struct{}, 1),
			agingTime: DefaultNatTimeout,
		}
		shard.m[key] = q
		go q.convoy()
	}
	q.refs.Add(1)
	shard.mu.Unlock()

	return q
}

func (p *UdpTaskPool) shardFor(key netip.AddrPort) *udpTaskShard {
	idx := int(hashAddrPort(key) & uint64(udpTaskPoolShardCount-1))
	return &p.shards[idx]
}

var (
	DefaultUdpTaskPool = NewUdpTaskPool()
)
