/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkDispatchPattern_Goroutine benchmarks the OLD pattern: direct goroutine spawn.
func BenchmarkDispatchPattern_Goroutine(b *testing.B) {
	var counter atomic.Int64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Old pattern: direct goroutine
			go func() {
				counter.Add(1)
			}()
		}
	})
}

// BenchmarkDispatchPattern_TaskRunner benchmarks the NEW pattern: UdpUnorderedTaskRunner.
func BenchmarkDispatchPattern_TaskRunner(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := newDefaultUdpUnorderedTaskRunner(ctx)

	src := mustParseAddrPort("192.168.1.1:12345")
	dst := mustParseAddrPort("8.8.8.8:53")
	key := NewUdpFlowKey(src, dst)
	var counter atomic.Int64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			task := func() {
				counter.Add(1)
			}
			if !runner.Submit(key, task) {
				// Task dropped - simulate packet drop
				counter.Add(-1)
			}
		}
	})

	cancel()
}

// BenchmarkDispatchPattern_MultiFlow_DNS benchmarks multiple DNS flows (realistic scenario).
func BenchmarkDispatchPattern_MultiFlow_DNS(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := newDefaultUdpUnorderedTaskRunner(ctx)

	// Simulate multiple DNS flows from different clients
	flows := []UdpFlowKey{
		NewUdpFlowKey(mustParseAddrPort("192.168.1.1:12345"), mustParseAddrPort("8.8.8.8:53")),
		NewUdpFlowKey(mustParseAddrPort("192.168.1.2:12346"), mustParseAddrPort("8.8.8.8:53")),
		NewUdpFlowKey(mustParseAddrPort("192.168.1.3:12347"), mustParseAddrPort("8.8.8.8:53")),
		NewUdpFlowKey(mustParseAddrPort("192.168.1.4:12348"), mustParseAddrPort("1.1.1.1:53")),
		NewUdpFlowKey(mustParseAddrPort("192.168.1.5:12349"), mustParseAddrPort("1.1.1.1:53")),
	}
	var counter atomic.Int64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := flows[i%len(flows)]
			i++
			task := func() {
				counter.Add(1)
				time.Sleep(10 * time.Microsecond) // Simulate minimal work
			}
			if !runner.Submit(key, task) {
				// Task dropped
			}
		}
	})

	cancel()
}

// BenchmarkDispatchPattern_MultiFlow_DNS_Old benchmarks multiple DNS flows with old pattern.
func BenchmarkDispatchPattern_MultiFlow_DNS_Old(b *testing.B) {
	// Simulate multiple DNS flows from different clients
	flows := []UdpFlowKey{
		NewUdpFlowKey(mustParseAddrPort("192.168.1.1:12345"), mustParseAddrPort("8.8.8.8:53")),
		NewUdpFlowKey(mustParseAddrPort("192.168.1.2:12346"), mustParseAddrPort("8.8.8.8:53")),
		NewUdpFlowKey(mustParseAddrPort("192.168.1.3:12347"), mustParseAddrPort("8.8.8.8:53")),
		NewUdpFlowKey(mustParseAddrPort("192.168.1.4:12348"), mustParseAddrPort("1.1.1.1:53")),
		NewUdpFlowKey(mustParseAddrPort("192.168.1.5:12349"), mustParseAddrPort("1.1.1.1:53")),
	}
	var counter atomic.Int64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := flows[i%len(flows)]
			i++
			go func(k UdpFlowKey) {
				counter.Add(1)
				time.Sleep(10 * time.Microsecond) // Simulate minimal work
			}(key)
		}
	})
}

// BenchmarkDispatchPattern_HighContention benchmarks high contention scenario.
func BenchmarkDispatchPattern_HighContention(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := newDefaultUdpUnorderedTaskRunner(ctx)

	// All tasks go to the same flow (high contention)
	src := mustParseAddrPort("192.168.1.1:12345")
	dst := mustParseAddrPort("8.8.8.8:53")
	key := NewUdpFlowKey(src, dst)
	var counter atomic.Int64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			task := func() {
				counter.Add(1)
			}
			if !runner.Submit(key, task) {
				// Task dropped
			}
		}
	})

	cancel()
}

// BenchmarkDispatchPattern_HighContention_Old benchmarks high contention with old pattern.
func BenchmarkDispatchPattern_HighContention_Old(b *testing.B) {
	var counter atomic.Int64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			go func() {
				counter.Add(1)
			}()
		}
	})
}
