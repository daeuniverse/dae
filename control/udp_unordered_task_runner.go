/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"math/bits"
	"runtime"
)

const (
	DefaultUdpUnorderedWorkers          = 0
	// Benchmarked via BenchmarkUdpUnorderedTaskRunner_QueueSizeSweep_HighPPS.
	// 1024 materially reduces drop rate for multi-flow high-PPS bursts compared
	// with 256/512, while hot-key overload remains worker-bound and does not
	// benefit from even deeper queues.
	DefaultUdpUnorderedQueueSizePerWorker = 1024
	defaultUdpUnorderedOverflowWorkerDivisor = 4
	defaultUdpUnorderedOverflowWorkerCap     = 4
)

type udpUnorderedTaskRunner struct {
	ctx      context.Context
	queues   []chan UdpTask
	overflow chan UdpTask
}

func newUdpUnorderedTaskRunner(ctx context.Context, workers, queueSizePerWorker int) *udpUnorderedTaskRunner {
	return newUdpUnorderedTaskRunnerWithOverflow(ctx, workers, queueSizePerWorker, 0, 0)
}

func newDefaultUdpUnorderedTaskRunner(ctx context.Context) *udpUnorderedTaskRunner {
	workers := runtime.GOMAXPROCS(0)
	if workers <= 0 {
		workers = 1
	}
	queueSizePerWorker := DefaultUdpUnorderedQueueSizePerWorker
	overflowWorkers := defaultUdpUnorderedOverflowWorkers(workers)
	overflowQueueSize := defaultUdpUnorderedOverflowQueueSize(queueSizePerWorker, overflowWorkers)
	return newUdpUnorderedTaskRunnerWithOverflow(ctx, workers, queueSizePerWorker, overflowWorkers, overflowQueueSize)
}

func newUdpUnorderedTaskRunnerWithOverflow(ctx context.Context, workers, queueSizePerWorker, overflowWorkers, overflowQueueSize int) *udpUnorderedTaskRunner {
	if ctx == nil {
		ctx = context.Background()
	}
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
		if workers <= 0 {
			workers = 1
		}
	}
	if queueSizePerWorker <= 0 {
		queueSizePerWorker = DefaultUdpUnorderedQueueSizePerWorker
	}

	r := &udpUnorderedTaskRunner{
		ctx:    ctx,
		queues: make([]chan UdpTask, workers),
	}
	for i := range workers {
		q := make(chan UdpTask, queueSizePerWorker)
		r.queues[i] = q
		go r.worker(q)
	}
	if overflowWorkers > 0 && overflowQueueSize > 0 {
		r.overflow = make(chan UdpTask, overflowQueueSize)
		for i := 0; i < overflowWorkers; i++ {
			go r.worker(r.overflow)
		}
	}
	return r
}

func defaultUdpUnorderedOverflowWorkers(workers int) int {
	if workers <= 0 {
		return 1
	}
	overflowWorkers := workers / defaultUdpUnorderedOverflowWorkerDivisor
	if overflowWorkers < 1 {
		overflowWorkers = 1
	}
	if overflowWorkers > defaultUdpUnorderedOverflowWorkerCap {
		overflowWorkers = defaultUdpUnorderedOverflowWorkerCap
	}
	return overflowWorkers
}

func defaultUdpUnorderedOverflowQueueSize(queueSizePerWorker, overflowWorkers int) int {
	if queueSizePerWorker <= 0 || overflowWorkers <= 0 {
		return 0
	}
	return queueSizePerWorker * overflowWorkers
}

func (r *udpUnorderedTaskRunner) Submit(key UdpFlowKey, task UdpTask) bool {
	if r == nil || task == nil || len(r.queues) == 0 {
		return false
	}
	q := r.queues[r.queueIndex(key)]
	select {
	case <-r.ctx.Done():
		return false
	case q <- task:
		return true
	default:
	}
	if r.overflow == nil {
		return false
	}
	select {
	case <-r.ctx.Done():
		return false
	case r.overflow <- task:
		return true
	default:
		return false
	}
}

func (r *udpUnorderedTaskRunner) worker(q <-chan UdpTask) {
	for {
		select {
		case <-r.ctx.Done():
			return
		case task := <-q:
			if task != nil {
				task()
			}
		}
	}
}

func (r *udpUnorderedTaskRunner) queueIndex(key UdpFlowKey) int {
	if len(r.queues) == 1 {
		return 0
	}
	h1 := hashAddrPort(key.Src)
	h2 := hashAddrPort(key.Dst)
	h := h1 ^ bits.RotateLeft64(h2, 1)
	return int(h % uint64(len(r.queues)))
}