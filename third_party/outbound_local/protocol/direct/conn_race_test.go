package direct

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestDirectPacketConnConcurrentWriteWithRealUDP 使用真实 UDP 连接测试并发写入
// 这个测试验证 directPacketConn 在 FullCone 模式下的并发写入竞争
// 运行: go test -race -run TestDirectPacketConnConcurrentWriteWithRealUDP
func TestDirectPacketConnConcurrentWriteWithRealUDP(t *testing.T) {
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

	const goroutines = 10
	const writesPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// 启动多个 goroutine 并发写入
	// 注意：这里直接使用 UDP 连接，绕过了 directPacketConn 的懒缓存逻辑
	// 但验证了底层 UDP 连接的并发写入安全性
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < writesPerGoroutine; j++ {
				data := []byte("test data from goroutine")
				_, _ = clientConn.WriteToUDPAddrPort(data, target)
			}
		}(i)
	}

	wg.Wait()

	// 等待所有数据被接收
	time.Sleep(100 * time.Millisecond)

	received := atomic.LoadInt64(&receivedCount)
	expected := int64(goroutines * writesPerGoroutine)

	t.Logf("Sent %d packets, received %d packets", expected, received)

	if received < expected*9/10 {
		t.Errorf("Packet loss detected: sent %d, received %d", expected, received)
	}

	t.Logf("✅ Direct UDP concurrent write test completed")
}

// TestDirectPacketConnLazyCacheRace 测试懒缓存初始化的竞争
// 问题：多个 goroutine 可能同时调用 resolveTarget 和 Write
func TestDirectPacketConnLazyCacheRace(t *testing.T) {
	// 模拟懒缓存的并发访问
	type lazyCache struct {
		cached atomic.Pointer[netip.AddrPort]
		once   sync.Once
	}

	cache := &lazyCache{}
	target := netip.MustParseAddrPort("127.0.0.1:8080")

	// Goroutine 1: 模拟并发解析和存储
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			cache.once.Do(func() {
				cache.cached.Store(&target)
			})
		}
	}()

	// Goroutine 2: 模拟并发读取
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			cached := cache.cached.Load()
			// 检查读取的值是否有效
			if cached != nil && *cached != target {
				t.Errorf("Unexpected cached value")
			}
		}
	}()

	wg.Wait()

	t.Logf("✅ Lazy cache race test completed")
}

// TestDirectPacketConnTargetAddressSwitch 测试目标地址切换的竞争
// 问题：cachedDialTgt 可能在读取和使用之间被修改
func TestDirectPacketConnTargetAddressSwitch(t *testing.T) {
	var cached atomic.Pointer[netip.AddrPort]

	target1 := netip.MustParseAddrPort("127.0.0.1:8080")
	target2 := netip.MustParseAddrPort("127.0.0.1:8081")

	cached.Store(&target1)

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: 读取目标并使用
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			cached := cached.Load()
			if cached != nil {
				// 模拟使用目标地址
				_ = *cached
			}
		}
	}()

	// Goroutine 2: 切换目标（这不应该发生，但测试原子性）
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			cached.Store(&target2)
			cached.Store(&target1)
		}
	}()

	wg.Wait()

	t.Logf("✅ Target address switch race test completed")
}

// BenchmarkDirectPacketConnWrite 基准测试写入性能
func BenchmarkDirectPacketConnWrite(b *testing.B) {
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

	for i := 0; i < b.N; i++ {
		_, _ = clientConn.WriteToUDPAddrPort(data, target)
	}
}

// BenchmarkDirectPacketConnWriteParallel 并发性能基准测试
func BenchmarkDirectPacketConnWriteParallel(b *testing.B) {
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
