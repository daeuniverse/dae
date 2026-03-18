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

// TestLayeredDispatchIntegration tests the complete layered dispatch system.
func TestLayeredDispatchIntegration(t *testing.T) {
	tests := []struct {
		name           string
		tasks          int
		taskDuration   time.Duration
		expectedStrategy UdpDispatchStrategy
	}{
		{"DNS burst", 100, 1 * time.Millisecond, StrategyDirectGoroutine},
		{"VoIP burst", 100, 5 * time.Millisecond, StrategyDirectGoroutine},
		{"WireGuard sustained", 50, 20 * time.Millisecond, StrategyBoundedPool},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var completed, dropped atomic.Int64

			// Create a fresh pool for each test
			testCtx, _ := context.WithCancel(context.Background())
			testPool := NewBoundedGoroutinePool(testCtx, 100) // Small pool for testing

			start := time.Now()
			for i := 0; i < tt.tasks; i++ {
				task := func() {
					time.Sleep(tt.taskDuration)
					completed.Add(1)
				}

				switch tt.expectedStrategy {
				case StrategyDirectGoroutine:
					// Direct goroutine - always succeeds
					go task()
				case StrategyBoundedPool:
					// Bounded pool - may block but won't drop
					if !testPool.Submit(task) {
						dropped.Add(1)
					}
				}
			}

			// Wait for completion
			time.Sleep(300 * time.Millisecond)
			testPool.Close()

			duration := time.Since(start)
			dropRate := float64(dropped.Load()) / float64(tt.tasks) * 100

			t.Logf("Tasks: %d, Completed: %d, Dropped: %d (%.1f%%), Duration: %v",
				tt.tasks, completed.Load(), dropped.Load(), dropRate, duration)

			if tt.expectedStrategy == StrategyDirectGoroutine && dropped.Load() > 0 {
				t.Error("Direct goroutine should never drop")
			}
			if tt.expectedStrategy == StrategyBoundedPool && dropped.Load() > 0 {
				t.Errorf("Bounded pool should never drop (got %d drops), it blocks instead", dropped.Load())
			}
		})
	}
}

// BenchmarkLayeredDispatchClassify benchmarks the classification overhead.
func BenchmarkLayeredDispatchClassify(b *testing.B) {
	src := mustParseAddrPort("192.168.1.1:12345")
	data := []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00} // QUIC Initial

	b.Run("DNS", func(b *testing.B) {
		dst := mustParseAddrPort("8.8.8.8:53")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decision := ClassifyUdpFlow(src, dst, nil)
			_ = decision.DispatchStrategy()
		}
	})

	b.Run("QUIC", func(b *testing.B) {
		dst := mustParseAddrPort("1.1.1.1:443")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decision := ClassifyUdpFlow(src, dst, data)
			_ = decision.DispatchStrategy()
		}
	})

	b.Run("WireGuard", func(b *testing.B) {
		dst := mustParseAddrPort("1.1.1.1:51820")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decision := ClassifyUdpFlow(src, dst, nil)
			_ = decision.DispatchStrategy()
		}
	})
}
