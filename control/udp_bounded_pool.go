/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
)

// BoundedGoroutinePool provides concurrency control with blocking semantics.
// Unlike a queue that drops packets when full, this blocks the submitter,
// providing backpressure while ensuring no packets are dropped.
type BoundedGoroutinePool struct {
	semaphore chan struct{}
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc

	// Metrics
	active atomic.Int64
	total  atomic.Int64
}

// NewBoundedGoroutinePool creates a pool with maximum concurrent goroutines.
// If maxGoroutines <= 0, it defaults to GOMAXPROCS * 8.
func NewBoundedGoroutinePool(ctx context.Context, maxGoroutines int) *BoundedGoroutinePool {
	if maxGoroutines <= 0 {
		maxGoroutines = runtime.GOMAXPROCS(0) * 8
	}
	poolCtx, cancel := context.WithCancel(ctx)
	return &BoundedGoroutinePool{
		semaphore: make(chan struct{}, maxGoroutines),
		ctx:       poolCtx,
		cancel:    cancel,
	}
}

// Submit submits a task to the pool. It blocks if the pool is at capacity,
// providing backpressure instead of dropping packets. Returns false if
// the pool has been stopped.
func (p *BoundedGoroutinePool) Submit(task func()) bool {
	select {
	case <-p.ctx.Done():
		return false
	case p.semaphore <- struct{}{}:
		p.wg.Add(1)
		p.total.Add(1)
		go func() {
			defer p.wg.Done()
			defer func() { <-p.semaphore }()
			p.active.Add(1)
			defer p.active.Add(-1)
			task()
		}()
		return true
	}
}

// Close waits for all submitted tasks to complete.
func (p *BoundedGoroutinePool) Close() {
	p.cancel()
	p.wg.Wait()
}

// udpBoundedPoolManager manages the bounded goroutine pool for UDP traffic.
type udpBoundedPoolManager struct {
	generalPool *BoundedGoroutinePool
}

func newUdpBoundedPoolManager(ctx context.Context) *udpBoundedPoolManager {
	// Pool size based on CPU cores to balance concurrency and context switching.
	// Use 16x cores for UDP traffic which can be bursty.
	poolSize := runtime.GOMAXPROCS(0) * 16

	return &udpBoundedPoolManager{
		generalPool: NewBoundedGoroutinePool(ctx, poolSize),
	}
}

func (m *udpBoundedPoolManager) Submit(task func()) bool {
	return m.generalPool.Submit(task)
}

func (m *udpBoundedPoolManager) Close() {
	m.generalPool.Close()
}
