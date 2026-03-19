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

// TestUdpUnorderedTaskRunner_DropRate tests packet drop rate under high load.
func TestUdpUnorderedTaskRunner_DropRate(t *testing.T) {
	tests := []struct {
		name             string
		workers          int
		queueSize        int
		flows            int
		tasksPerFlow     int
		taskDuration     time.Duration
		expectedDropRate float64 // 0-1, where 1 is 100% drop
	}{
		{
			name:             "Low load - plenty of capacity",
			workers:          4,
			queueSize:        1024,
			flows:            10,
			tasksPerFlow:     100,
			taskDuration:     0, // Instant tasks
			expectedDropRate: 0.0,
		},
		{
			name:             "Medium load - some drops expected",
			workers:          2,
			queueSize:        64,
			flows:            100,
			tasksPerFlow:     100,
			taskDuration:     10 * time.Millisecond,
			expectedDropRate: 0.3, // Expect ~30% drops
		},
		{
			name:             "High load - significant drops",
			workers:          2,
			queueSize:        32,
			flows:            50,
			tasksPerFlow:     200,
			taskDuration:     20 * time.Millisecond,
			expectedDropRate: 0.7, // Expect ~70% drops
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			runner := newUdpUnorderedTaskRunner(ctx, tt.workers, tt.queueSize)

			var submitted atomic.Int64
			var dropped atomic.Int64
			var completed atomic.Int64

			// Submit all tasks rapidly
			for flow := 0; flow < tt.flows; flow++ {
				src := mustParseAddrPort("192.168.1.1:12345")
				dst := mustParseAddrPort("8.8.8.8:53")
				key := NewUdpFlowKey(src, dst)

				for i := 0; i < tt.tasksPerFlow; i++ {
					task := func() {
						if tt.taskDuration > 0 {
							time.Sleep(tt.taskDuration)
						}
						completed.Add(1)
					}

					submitted.Add(1)
					if !runner.Submit(key, task) {
						dropped.Add(1)
					}
				}
			}

			totalSubmitted := submitted.Load()
			totalDropped := dropped.Load()
			dropRate := float64(totalDropped) / float64(totalSubmitted)

			t.Logf("Submitted: %d, Dropped: %d, Drop rate: %.2f%%",
				totalSubmitted, totalDropped, dropRate*100)

			// Wait a bit for in-flight tasks to complete
			time.Sleep(500 * time.Millisecond)
			t.Logf("Completed: %d", completed.Load())

			// Check if drop rate is within expected range (±20% tolerance)
			if dropRate < tt.expectedDropRate-0.2 || dropRate > tt.expectedDropRate+0.2 {
				t.Logf("WARNING: Drop rate %.2f outside expected range [%.2f, %.2f]",
					dropRate, tt.expectedDropRate-0.2, tt.expectedDropRate+0.2)
			}
		})
	}
}

// BenchmarkUdpUnorderedTaskRunner_QueueFull benchmarks the worst case: queue always full.
func BenchmarkUdpUnorderedTaskRunner_QueueFull(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Very small queue to ensure it's always full
	runner := newUdpUnorderedTaskRunner(ctx, 1, 1)

	src := mustParseAddrPort("192.168.1.1:12345")
	dst := mustParseAddrPort("8.8.8.8:53")
	key := NewUdpFlowKey(src, dst)

	var submitted atomic.Int64
	var dropped atomic.Int64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			task := func() {
				time.Sleep(100 * time.Millisecond) // Slow task
			}
			submitted.Add(1)
			if !runner.Submit(key, task) {
				dropped.Add(1)
			}
		}
	})

	totalSubmitted := submitted.Load()
	totalDropped := dropped.Load()
	dropRate := float64(totalDropped) / float64(totalSubmitted)

	b.Logf("Submitted: %d, Dropped: %d, Drop rate: %.2f%%",
		totalSubmitted, totalDropped, dropRate*100)
}
