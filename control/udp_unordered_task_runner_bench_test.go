/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

var udpUnorderedTaskRunnerBenchSink atomic.Uint64

func BenchmarkUdpUnorderedTaskRunner_QueueSizeSweep_HighPPS(b *testing.B) {
	workers := runtime.GOMAXPROCS(0)
	if workers <= 0 {
		workers = 1
	}

	queueSizes := []int{128, 256, 512, 1024}
	scenarios := []struct {
		name           string
		keyCount       int
		workIterations int
	}{
		{name: "many_keys_light", keyCount: workers * 64, workIterations: 256},
		{name: "many_keys_medium", keyCount: workers * 64, workIterations: 1024},
		{name: "hot_key_medium", keyCount: 1, workIterations: 1024},
	}

	for _, scenario := range scenarios {
		b.Run(scenario.name, func(b *testing.B) {
			for _, queueSize := range queueSizes {
				queueSize := queueSize
				b.Run(fmt.Sprintf("queue=%d", queueSize), func(b *testing.B) {
					benchmarkUdpUnorderedTaskRunnerHighPPS(b, workers, queueSize, 0, 0, scenario.keyCount, scenario.workIterations)
				})
			}
		})
	}
}

func BenchmarkUdpUnorderedTaskRunner_OverflowPool_HighPPS(b *testing.B) {
	workers := runtime.GOMAXPROCS(0)
	if workers <= 0 {
		workers = 1
	}
	queueSizePerWorker := DefaultUdpUnorderedQueueSizePerWorker
	defaultOverflowWorkers := defaultUdpUnorderedOverflowWorkers(workers)
	defaultOverflowQueueSize := defaultUdpUnorderedOverflowQueueSize(queueSizePerWorker, defaultOverflowWorkers)

	scenarios := []struct {
		name           string
		keyCount       int
		workIterations int
	}{
		{name: "many_keys_medium", keyCount: workers * 64, workIterations: 1024},
		{name: "hot_key_medium", keyCount: 1, workIterations: 1024},
	}
	variants := []struct {
		name              string
		overflowWorkers   int
		overflowQueueSize int
	}{
		{name: "no_overflow", overflowWorkers: 0, overflowQueueSize: 0},
		{name: "default_overflow", overflowWorkers: defaultOverflowWorkers, overflowQueueSize: defaultOverflowQueueSize},
	}

	for _, scenario := range scenarios {
		b.Run(scenario.name, func(b *testing.B) {
			for _, variant := range variants {
				variant := variant
				b.Run(variant.name, func(b *testing.B) {
					benchmarkUdpUnorderedTaskRunnerHighPPS(b, workers, queueSizePerWorker, variant.overflowWorkers, variant.overflowQueueSize, scenario.keyCount, scenario.workIterations)
				})
			}
		})
	}
}

func benchmarkUdpUnorderedTaskRunnerHighPPS(b *testing.B, workers, queueSizePerWorker, overflowWorkers, overflowQueueSize, keyCount, workIterations int) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runner := newUdpUnorderedTaskRunnerWithOverflow(ctx, workers, queueSizePerWorker, overflowWorkers, overflowQueueSize)
	keys := makeUdpUnorderedBenchKeys(keyCount)

	var seq atomic.Uint64
	var accepted atomic.Uint64
	var dropped atomic.Uint64
	var completed atomic.Uint64

	b.ReportAllocs()
	start := time.Now()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			idx := int(seq.Add(1)-1) % len(keys)
			key := keys[idx]
			if runner.Submit(key, func() {
				udpUnorderedTaskRunnerBenchWork(workIterations)
				completed.Add(1)
			}) {
				accepted.Add(1)
			} else {
				dropped.Add(1)
			}
		}
	})
	measured := time.Since(start)
	b.StopTimer()

	deadline := time.Now().Add(10 * time.Second)
	for completed.Load() < accepted.Load() && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if got, want := completed.Load(), accepted.Load(); got != want {
		b.Fatalf("unfinished tasks: completed=%d accepted=%d", got, want)
	}

	total := accepted.Load() + dropped.Load()
	if total == 0 {
		b.Fatal("benchmark executed zero submissions")
	}
	b.ReportMetric(float64(accepted.Load())*100/float64(total), "accept%")
	b.ReportMetric(float64(dropped.Load())*100/float64(total), "drop%")
	b.ReportMetric(float64(queueSizePerWorker), "queue_size")
	b.ReportMetric(float64(workers), "workers")
	b.ReportMetric(float64(overflowWorkers), "overflow_workers")
	b.ReportMetric(float64(overflowQueueSize), "overflow_queue_size")
	if measured > 0 {
		b.ReportMetric(float64(accepted.Load())/measured.Seconds(), "accepted_ops/s")
		b.ReportMetric(float64(dropped.Load())/measured.Seconds(), "dropped_ops/s")
	}
}

func makeUdpUnorderedBenchKeys(keyCount int) []UdpFlowKey {
	if keyCount <= 0 {
		keyCount = 1
	}
	keys := make([]UdpFlowKey, 0, keyCount)
	for i := 0; i < keyCount; i++ {
		keys = append(keys, UdpFlowKey{
			Src: netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), uint16(10000+(i%50000))),
			Dst: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}), uint16(20000+(i%40000))),
		})
	}
	return keys
}

func udpUnorderedTaskRunnerBenchWork(iterations int) {
	if iterations <= 0 {
		iterations = 1
	}
	var x uint64 = 0x9e3779b97f4a7c15
	for i := 0; i < iterations; i++ {
		x ^= uint64(i) + 0x9e3779b97f4a7c15 + (x << 6) + (x >> 2)
	}
	udpUnorderedTaskRunnerBenchSink.Add(x)
}