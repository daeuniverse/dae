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

const UdpTaskQueueLength = 128

type UdpTask = func()

// UdpTaskQueue make sure packets with the same key (4 tuples) will be sent in order.
type UdpTaskQueue struct {
	key       string
	p         *UdpTaskPool
	ch        chan UdpTask
	agingTime time.Duration
	refs      atomic.Int32
}

func (q *UdpTaskQueue) convoy() {
	timer := time.NewTimer(q.agingTime)
	defer timer.Stop()

	for {
		select {
		case task := <-q.ch:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}

			task()
			timer.Reset(q.agingTime)
		case <-timer.C:
			// Idle GC: only remove queue when no in-flight EmitTask and no pending tasks.
			q.p.mu.Lock()
			current, ok := q.p.m[q.key]
			if ok && current == q && q.refs.Load() == 0 && len(q.ch) == 0 {
				delete(q.p.m, q.key)
				q.p.mu.Unlock()
				if len(q.ch) == 0 {
					q.p.queueChPool.Put(q.ch)
				}
				return
			}
			q.p.mu.Unlock()
			timer.Reset(q.agingTime)
		}
	}
}

type UdpTaskPool struct {
	queueChPool sync.Pool
	// mu protects m
	mu sync.RWMutex
	m  map[string]*UdpTaskQueue
}

func NewUdpTaskPool() *UdpTaskPool {
	p := &UdpTaskPool{
		queueChPool: sync.Pool{New: func() any {
			return make(chan UdpTask, UdpTaskQueueLength)
		}},
		mu: sync.RWMutex{},
		m:  map[string]*UdpTaskQueue{},
	}
	return p
}

// EmitTask: Make sure packets with the same key (4 tuples) will be sent in order.
func (p *UdpTaskPool) EmitTask(key string, task UdpTask) {
	for {
		q := p.acquireQueue(key)
		select {
		case q.ch <- task:
			q.refs.Add(-1)
			return
		default:
			// Queue is full; block send to preserve packet order for this key.
			q.ch <- task
			q.refs.Add(-1)
			return
		}
	}
}

func (p *UdpTaskPool) acquireQueue(key string) *UdpTaskQueue {
	p.mu.RLock()
	if q, ok := p.m[key]; ok {
		q.refs.Add(1)
		p.mu.RUnlock()
		return q
	}
	p.mu.RUnlock()

	p.mu.Lock()
	q, ok := p.m[key]
	if !ok {
		ch := p.queueChPool.Get().(chan UdpTask)
		q = &UdpTaskQueue{
			key:       key,
			p:         p,
			ch:        ch,
			agingTime: DefaultNatTimeout,
		}
		p.m[key] = q
		go q.convoy()
	}
	q.refs.Add(1)
	p.mu.Unlock()

	return q
}

var (
	DefaultUdpTaskPool = NewUdpTaskPool()
)
