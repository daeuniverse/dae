package control

import (
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func BenchmarkUdpTaskPool_Simple(b *testing.B) {
	pool := NewUdpTaskPool()
	key := netip.MustParseAddrPort("192.168.1.1:12345")
	var count atomic.Int64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pool.EmitTask(key, func() {
				count.Add(1)
			})
		}
	})
}

func BenchmarkQuicReassemblyPool_Simple(b *testing.B) {
	pool := NewQuicReassemblyPool()
	key := netip.MustParseAddrPort("192.168.1.1:12345")
	var count atomic.Int64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pool.Emit(key, []byte("test"), func(accumulated []byte) {
				count.Add(1)
			})
		}
	})
}

func BenchmarkUdpTaskPool_ManyKeys(b *testing.B) {
	pool := NewUdpTaskPool()
	var count atomic.Int64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := netip.MustParseAddrPort(fmt.Sprintf("192.168.%d.%d:12345", (i/256)%256, i%256))
			pool.EmitTask(key, func() {
				count.Add(1)
			})
			i++
		}
	})
}

func BenchmarkQuicReassemblyPool_ManyKeys(b *testing.B) {
	pool := NewQuicReassemblyPool()
	var count atomic.Int64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := netip.MustParseAddrPort(fmt.Sprintf("192.168.%d.%d:12345", (i/256)%256, i%256))
			pool.Emit(key, []byte("test"), func(accumulated []byte) {
				count.Add(1)
			})
			i++
		}
	})
}

func BenchmarkUdpTaskPool_Memory(b *testing.B) {
	pool := NewUdpTaskPool()

	var memBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := netip.MustParseAddrPort(fmt.Sprintf("10.0.%d.%d:443", (i/256)%256, i%256))
		pool.EmitTask(key, func() {})
	}

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	b.ReportMetric(float64(memAfter.Alloc-memBefore.Alloc)/float64(b.N), "bytes/op")
}

func BenchmarkQuicReassemblyPool_Memory(b *testing.B) {
	pool := NewQuicReassemblyPool()

	var memBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := netip.MustParseAddrPort(fmt.Sprintf("10.0.%d.%d:443", (i/256)%256, i%256))
		pool.Emit(key, []byte("test"), func(accumulated []byte) {})
	}

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	b.ReportMetric(float64(memAfter.Alloc-memBefore.Alloc)/float64(b.N), "bytes/op")
}

func TestQuicReassemblyPool_Ordering(t *testing.T) {
	pool := NewQuicReassemblyPool()
	key := netip.MustParseAddrPort("192.168.1.1:443")

	var mu sync.Mutex
	results := make([]int, 0, 100)

	for i := 0; i < 100; i++ {
		i := i
		pool.Emit(key, []byte{byte(i)}, func(accumulated []byte) {
			mu.Lock()
			results = append(results, i)
			mu.Unlock()
		})
	}

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(results) != 100 {
		t.Fatalf("expected 100 results, got %d", len(results))
	}

	for i, v := range results {
		if v != i {
			t.Fatalf("order not preserved: results[%d] = %d", i, v)
		}
	}
}

func TestQuicReassemblyPool_Accumulation(t *testing.T) {
	pool := NewQuicReassemblyPool()
	key := netip.MustParseAddrPort("192.168.1.1:443")

	var accumulated []byte
	var done bool

	for i := 0; i < 5; i++ {
		pool.EmitWithDone(key, []byte{byte(i)}, func(buf []byte) bool {
			accumulated = append([]byte{}, buf...)
			if len(buf) >= 5 {
				done = true
				return true
			}
			return false
		})
	}

	if !done {
		t.Fatal("expected accumulation to complete")
	}

	if len(accumulated) != 5 {
		t.Fatalf("expected 5 bytes, got %d", len(accumulated))
	}

	for i, b := range accumulated {
		if b != byte(i) {
			t.Fatalf("expected byte %d, got %d", i, b)
		}
	}
}

func TestQuicReassemblyPool_Cleanup(t *testing.T) {
	pool := NewQuicReassemblyPool()
	key := netip.MustParseAddrPort("192.168.1.1:443")

	pool.Emit(key, []byte("test"), func(accumulated []byte) {})

	idx := pool.shardIdx(key)
	shard := &pool.shards[idx]

	shard.Lock()
	if len(shard.sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(shard.sessions))
	}
	shard.Unlock()

	time.Sleep(quicSessionTimeout + 100*time.Millisecond)
	pool.CleanupExpired()

	shard.Lock()
	if len(shard.sessions) != 0 {
		t.Fatalf("expected 0 sessions after cleanup, got %d", len(shard.sessions))
	}
	shard.Unlock()
}

func TestQuicReassemblyPool_GoroutineCount(t *testing.T) {
	before := runtime.NumGoroutine()

	pool := NewQuicReassemblyPool()

	for i := 0; i < 1000; i++ {
		key := netip.MustParseAddrPort(fmt.Sprintf("192.168.%d.%d:443", (i/256)%256, i%256))
		pool.Emit(key, []byte("test"), func(accumulated []byte) {})
	}

	after := runtime.NumGoroutine()

	if after-before > 10 {
		t.Logf("WARNING: goroutine count increased by %d (before: %d, after: %d)", after-before, before, after)
	}
}

func TestUdpTaskPool_GoroutineCount(t *testing.T) {
	before := runtime.NumGoroutine()

	pool := NewUdpTaskPool()

	for i := 0; i < 1000; i++ {
		key := netip.MustParseAddrPort(fmt.Sprintf("192.168.%d.%d:443", (i/256)%256, i%256))
		pool.EmitTask(key, func() {})
	}

	time.Sleep(50 * time.Millisecond)
	after := runtime.NumGoroutine()

	if after-before > 100 {
		t.Logf("UdpTaskPool: goroutine count increased by %d (before: %d, after: %d)", after-before, before, after)
	}
}
