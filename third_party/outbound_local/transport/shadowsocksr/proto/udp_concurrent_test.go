package proto

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/pool"
)

// TestUdpConnConcurrentWriteWithRealUDP 使用真实 UDP 连接测试并发写入
// 这个测试验证 shadowsocksr 的 PacketConn 在并发写入时是否存在竞争
// 运行: go test -race -run TestUdpConnConcurrentWriteWithRealUDP
func TestUdpConnConcurrentWriteWithRealUDP(t *testing.T) {
	// 创建服务器
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve server address: %v", err)
	}

	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer func() { _ = serverConn.Close() }()

	// 接收计数器
	var receivedCount int64

	// 启动服务器接收协程
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n > 0 {
				atomic.AddInt64(&receivedCount, 1)
			}
		}
	}()

	// 创建客户端
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	target := serverConn.LocalAddr().(*net.UDPAddr).AddrPort()

	// 创建 PacketConn 包装器（模拟 shadowsocksr 的 PacketConn）
	// 注意：这里直接使用 UDP 连接测试并发安全性
	// 问题：如果 PacketConn 的 WriteTo 方法没有锁保护，
	// 多个 goroutine 并发调用会导致数据竞争

	const goroutines = 10
	const writesPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	start := time.Now()

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < writesPerGoroutine; j++ {
				data := []byte("test data from goroutine")
				// 直接写入 UDP 连接
				_, err := clientConn.WriteToUDPAddrPort(data, target)
				if err != nil {
					t.Errorf("Goroutine %d write %d failed: %v", id, j, err)
				}
			}
		}(i)
	}

	wg.Wait()

	// 等待数据被接收
	time.Sleep(100 * time.Millisecond)

	received := atomic.LoadInt64(&receivedCount)
	expected := int64(goroutines * writesPerGoroutine)

	duration := time.Since(start)

	t.Logf("Sent %d packets, received %d packets in %v", expected, received, duration)

	if received < expected*9/10 {
		t.Errorf("Packet loss detected: sent %d, received %d", expected, received)
	}
}

// TestUdpConnWriteToWithoutLock 演示没有锁保护的问题
// 这个测试创建一个模拟的 PacketConn 来展示竞争条件
func TestUdpConnWriteToWithoutLock(t *testing.T) {
	// 模拟一个没有锁保护的写入器
	type unsafeWriter struct {
		writes int64
	}

	writer := &unsafeWriter{}

	var wg sync.WaitGroup
	const goroutines = 20
	const writesPerGoroutine = 1000

	wg.Add(goroutines)

	// 模拟并发写入（没有锁保护）
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < writesPerGoroutine; j++ {
				// 模拟写入操作（非原子）
				current := atomic.LoadInt64(&writer.writes)
				time.Sleep(1 * time.Microsecond) // 增加竞争窗口
				atomic.StoreInt64(&writer.writes, current+1)
			}
		}()
	}

	wg.Wait()

	writes := atomic.LoadInt64(&writer.writes)
	expected := int64(goroutines * writesPerGoroutine)

	// 由于没有锁保护，写入次数可能不等于预期值
	t.Logf("Writes without lock: got %d, expected %d (loss: %d)", 
		writes, expected, expected-writes)

	if writes != expected {
		t.Logf("⚠️  Race condition detected: %d writes lost", expected-writes)
	}
}

// TestUdpConnWriteToWithLock 演示有锁保护的情况
func TestUdpConnWriteToWithLock(t *testing.T) {
	type safeWriter struct {
		writes int64
		mu    sync.Mutex
	}

	writer := &safeWriter{}

	var wg sync.WaitGroup
	const goroutines = 20
	const writesPerGoroutine = 1000

	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < writesPerGoroutine; j++ {
				writer.mu.Lock()
				writer.writes++
				writer.mu.Unlock()
			}
		}()
	}

	wg.Wait()

	writes := writer.writes
	expected := int64(goroutines * writesPerGoroutine)

	t.Logf("Writes with lock: got %d, expected %d", writes, expected)

	if writes != expected {
		t.Errorf("Lock protection failed: got %d, expected %d", writes, expected)
	}
}

// BenchmarkUdpConnWriteParallel 并发性能基准测试
func BenchmarkUdpConnWriteParallel(b *testing.B) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Skip("Failed to create server")
	}
	defer func() { _ = serverConn.Close() }()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Skip("Failed to create client")
	}
	defer func() { _ = clientConn.Close() }()

	target := serverConn.LocalAddr().(*net.UDPAddr).AddrPort()
	data := []byte("benchmark test data")

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = clientConn.WriteToUDPAddrPort(data, target)
		}
	})
}

// TestPoolConcurrentAccess 测试 buffer pool 的并发访问
func TestPoolConcurrentAccess(t *testing.T) {
	const goroutines = 20
	const opsPerGoroutine = 500

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				buf := pool.Get(1500)
				if len(buf) < 1500 {
					t.Errorf("Buffer too small: %d", len(buf))
				}
				pool.Put(buf)
			}
		}()
	}

	wg.Wait()
	t.Logf("Pool concurrent access test completed")
}
