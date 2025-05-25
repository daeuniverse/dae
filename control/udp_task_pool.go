/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
*/

package control

import (
	"context"
	"sync"
	"time"
)

const UdpTaskQueueLength = 128

type UdpTask = func()

// UdpTaskQueue make sure packets with the same key (4 tuples) will be sent in order.
type UdpTaskQueue struct {
	key       string
	p         *UdpTaskPool
	ch        chan UdpTask
	timer     *time.Timer
	agingTime time.Duration
	ctx       context.Context
	closed    chan struct{}
}

func (q *UdpTaskQueue) convoy() {
	for {
		select {
		case <-q.ctx.Done():
			close(q.closed)
			return
		case task := <-q.ch:
			task()
			q.timer.Reset(q.agingTime)
		}
	}
}

type UdpTaskPool struct {
	queueChPool sync.Pool
	// mu protects m
	mu sync.Mutex
	m  map[string]*UdpTaskQueue
}

func NewUdpTaskPool() *UdpTaskPool {
	p := &UdpTaskPool{
		queueChPool: sync.Pool{New: func() any {
			return make(chan UdpTask, UdpTaskQueueLength)
		}},
		mu: sync.Mutex{},
		m:  map[string]*UdpTaskQueue{},
	}
	return p
}

// EmitTask: Make sure packets with the same key (4 tuples) will be sent in order.
func (p *UdpTaskPool) EmitTask(key string, task UdpTask) {
	p.mu.Lock()
	q, ok := p.m[key]
	if !ok {
		ch := p.queueChPool.Get().(chan UdpTask)
		ctx, cancel := context.WithCancel(context.Background())
		q = &UdpTaskQueue{
			key:       key,
			p:         p,
			ch:        ch,
			timer:     nil,
			agingTime: DefaultNatTimeout,
			ctx:       ctx,
			closed:    make(chan struct{}),
		}
		q.timer = time.AfterFunc(q.agingTime, func() {
			// if timer executed, there should no task in queue.
			// q.closed should not blocking things.
			p.mu.Lock()
			cancel()
			delete(p.m, key)
			p.mu.Unlock()
			<-q.closed
			if len(ch) == 0 { // Otherwise let it be GCed
				p.queueChPool.Put(ch)
			}
		})
		p.m[key] = q
		go q.convoy()
	}
	p.mu.Unlock()
	// if task cannot be executed within 180s(DefaultNatTimeout), GC may be triggered, so skip the task when GC occurs
	select {
	case q.ch <- task:
	case <-q.ctx.Done():
	}
}

var (
	DefaultUdpTaskPool = NewUdpTaskPool()
)
