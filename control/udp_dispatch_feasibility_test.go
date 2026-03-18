/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// TestGoroutineVsTaskRunner compares goroutine spawn vs task runner.
func TestGoroutineVsTaskRunner(t *testing.T) {
	tests := []struct {
		name         string
		tasks        int
		workDuration time.Duration
		concurrency  int
	}{
		{"Low load", 1000, 0, 10},
		{"Medium load", 10000, 10 * time.Microsecond, 100},
		{"High load", 50000, 50 * time.Microsecond, 500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test with goroutine
			var goroutineCompleted atomic.Int64
			var goroutineMaxGoroutines atomic.Int64
			startGoroutines := runtime.NumGoroutine()

			start := time.Now()
			for i := 0; i < tt.tasks; i++ {
				current := runtime.NumGoroutine()
				for {
					max := goroutineMaxGoroutines.Load()
					if int64(current) <= max || goroutineMaxGoroutines.CompareAndSwap(max, int64(current)) {
						break
					}
				}
				go func() {
					if tt.workDuration > 0 {
						time.Sleep(tt.workDuration)
					}
					goroutineCompleted.Add(1)
				}()
			}

			// Wait for completion
			for goroutineCompleted.Load() < int64(tt.tasks) && time.Since(start) < 10*time.Second {
				time.Sleep(10 * time.Millisecond)
			}
			goroutineDuration := time.Since(start)

			// Test with task runner
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			runner := newUdpUnorderedTaskRunner(ctx, runtime.GOMAXPROCS(0), DefaultUdpUnorderedQueueSizePerWorker)

			var runnerCompleted atomic.Int64
			var runnerDropped atomic.Int64

			start = time.Now()
			for i := 0; i < tt.tasks; i++ {
				task := func() {
					if tt.workDuration > 0 {
						time.Sleep(tt.workDuration)
					}
					runnerCompleted.Add(1)
				}
				if !runner.Submit(NewUdpFlowKey(mustParseAddrPort("192.168.1.1:12345"), mustParseAddrPort("1.1.1.1:53")), task) {
					runnerDropped.Add(1)
				}
			}

			// Wait for completion
			expectedCompletions := int64(tt.tasks) - runnerDropped.Load()
			for runnerCompleted.Load() < expectedCompletions && time.Since(start) < 10*time.Second {
				time.Sleep(10 * time.Millisecond)
			}
			runnerDuration := time.Since(start)

			t.Logf("Goroutine: completed=%d/%d, maxGoroutines=%d, duration=%v, dropRate=0%%",
				goroutineCompleted.Load(), tt.tasks, goroutineMaxGoroutines.Load()-int64(startGoroutines), goroutineDuration)
			t.Logf("TaskRunner: completed=%d/%d, dropped=%d, duration=%v, dropRate=%.2f%%",
				runnerCompleted.Load(), tt.tasks, runnerDropped.Load(), runnerDuration,
				float64(runnerDropped.Load())/float64(tt.tasks)*100)
		})
	}
}

// BenchmarkGoroutineOverhead benchmarks the overhead of goroutine spawn.
func BenchmarkGoroutineOverhead(b *testing.B) {
	b.Run("instant_task", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			go func() {
				runtime.KeepAlive(nil)
			}()
		}
	})

	b.Run("minimal_work", func(b *testing.B) {
		var sink atomic.Int64
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			go func() {
				sink.Add(1)
			}()
		}
	})
}

// BenchmarkGoroutineVsSubmit compares goroutine spawn vs task runner submission.
func BenchmarkGoroutineVsSubmit(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner := newDefaultUdpUnorderedTaskRunner(ctx)
	key := NewUdpFlowKey(mustParseAddrPort("192.168.1.1:12345"), mustParseAddrPort("1.1.1.1:53"))
	var sink atomic.Int64

	b.Run("goroutine", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			go func() {
				sink.Add(1)
			}()
		}
	})

	b.Run("task_runner", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			task := func() {
				sink.Add(1)
			}
			if !runner.Submit(key, task) {
				// Drop
			}
		}
	})
}

// TestNonDNSTrafficCharacteristics analyzes different non-DNS UDP traffic types.
func TestNonDNSTrafficCharacteristics(t *testing.T) {
	trafficTypes := []struct {
		name        string
		port        uint16
		description string
	}{
		{"WireGuard", 51820, "VPN traffic, long-lived, high throughput"},
		{"QUIC", 443, "HTTP/3, long-lived, low latency sensitive"},
		{"HTTP3", 443, "Similar to QUIC"},
		{"OpenVPN", 1194, "VPN traffic"},
		{"DTLS", 443, "TLS over UDP"},
		{"SIP", 5060, "VoIP signaling"},
		{"RTP", 5004, "VoIP media, very latency sensitive"},
		{"Generic_UDP", 0, "General UDP traffic"},
	}

	for _, tt := range trafficTypes {
		t.Run(tt.name, func(t *testing.T) {
			// Analyze characteristics
			isLatencySensitive := tt.name == "RTP" || tt.name == "SIP" || tt.name == "QUIC"
			isLongLived := tt.name == "WireGuard" || tt.name == "OpenVPN" || tt.name == "QUIC"
			isHighThroughput := tt.name == "WireGuard" || tt.name == "RTP"

			t.Logf("Port: %d", tt.port)
			t.Logf("Description: %s", tt.description)
			t.Logf("Latency sensitive: %v", isLatencySensitive)
			t.Logf("Long-lived: %v", isLongLived)
			t.Logf("High throughput: %v", isHighThroughput)
		})
	}
}
