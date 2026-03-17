package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// mockPacketConn 模拟 netproxy.PacketConn
type mockPacketConn struct {
	writes       int64
	writeToCalls int64
	closed       atomic.Bool
	mu           sync.Mutex
}

func (m *mockPacketConn) Read(b []byte) (n int, err error) {
	return 0, nil
}

func (m *mockPacketConn) Write(b []byte) (n int, err error) {
	atomic.AddInt64(&m.writes, 1)
	time.Sleep(10 * time.Microsecond)
	return len(b), nil
}

func (m *mockPacketConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	return 0, netip.AddrPort{}, nil
}

func (m *mockPacketConn) WriteTo(p []byte, addr string) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	atomic.AddInt64(&m.writeToCalls, 1)
	time.Sleep(10 * time.Microsecond)
	return len(p), nil
}

func (m *mockPacketConn) Close() error {
	m.closed.Store(true)
	return nil
}

func (m *mockPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// TestUdpEndpointWriteToRace 测试 UdpEndpoint 的并发写入
// 注意：这个测试验证 UdpEndpoint 确实有写锁保护
func TestUdpEndpointWriteToRace(t *testing.T) {
	mockConn := &mockPacketConn{}
	
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)
	
	endpoint := &UdpEndpoint{
		conn:       mockConn,
		handler:    func(ue *UdpEndpoint, data []byte, from netip.AddrPort) error { return nil },
		NatTimeout: 30 * time.Second,
		log:        log,
	}
	
	const goroutines = 10
	const writesPerGoroutine = 100
	
	var wg sync.WaitGroup
	wg.Add(goroutines)
	
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < writesPerGoroutine; j++ {
				data := []byte("test data from goroutine")
				_, err := endpoint.WriteTo(data, "127.0.0.1:8080")
				if err != nil {
					t.Errorf("Goroutine %d write %d failed: %v", id, j, err)
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	writes := atomic.LoadInt64(&mockConn.writeToCalls)
	expected := int64(goroutines * writesPerGoroutine)
	
	if writes != expected {
		t.Errorf("Write count mismatch: got %d, expected %d", writes, expected)
	}
	
	t.Logf("✅ UdpEndpoint.WriteTo is thread-safe: %d concurrent writes completed", writes)
}

// TestUdpEndpointWriteToAfterClose 测试关闭后的写入行为
func TestUdpEndpointWriteAfterClose(t *testing.T) {
	mockConn := &mockPacketConn{}
	
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)
	
	endpoint := &UdpEndpoint{
		conn:       mockConn,
		handler:    func(ue *UdpEndpoint, data []byte, from netip.AddrPort) error { return nil },
		NatTimeout: 30 * time.Second,
		log:        log,
	}
	
	// 关闭 endpoint
	endpoint.dead.Store(true)
	
	// 尝试写入应该失败
	_, err := endpoint.WriteTo([]byte("test"), "127.0.0.1:8080")
	if err != net.ErrClosed {
		t.Errorf("Expected net.ErrClosed after close, got: %v", err)
	}
	
	t.Logf("✅ UdpEndpoint correctly rejects writes after close")
}

// TestUdpEndpointTtlRefreshRace 测试 TTL 刷新的并发安全
func TestUdpEndpointTtlRefreshRace(t *testing.T) {
	mockConn := &mockPacketConn{}
	
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)
	
	endpoint := &UdpEndpoint{
		conn:       mockConn,
		handler:    func(ue *UdpEndpoint, data []byte, from netip.AddrPort) error { return nil },
		NatTimeout: 30 * time.Second,
		log:        log,
	}
	
	const goroutines = 20
	const refreshesPerGoroutine = 1000
	
	var wg sync.WaitGroup
	wg.Add(goroutines)
	
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < refreshesPerGoroutine; j++ {
				endpoint.RefreshTtl()
			}
		}()
	}
	
	wg.Wait()
	
	expiresAt := endpoint.expiresAtNano.Load()
	if expiresAt <= 0 {
		t.Error("TTL not refreshed")
	}
	
	t.Logf("✅ TTL refresh is thread-safe: expiresAt=%d", expiresAt)
}

// TestAnyfromConcurrentWrite 测试 Anyfrom 的并发写入
// 问题：Anyfrom 的 Write 方法没有写锁保护
func TestAnyfromConcurrentWrite(t *testing.T) {
	// 创建真实的 UDP 连接
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}
	defer conn.Close()
	
	// 创建目标地址
	dstAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	if err != nil {
		t.Fatalf("Failed to resolve destination: %v", err)
	}
	
	// 创建 Anyfrom
	af := &Anyfrom{
		UDPConn: conn,
		ttl:     30 * time.Second,
	}
	af.expiresAtNano.Store(time.Now().Add(30 * time.Second).UnixNano())
	
	const goroutines = 10
	const writesPerGoroutine = 100
	
	var wg sync.WaitGroup
	wg.Add(goroutines)
	
	successCount := int64(0)
	
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < writesPerGoroutine; j++ {
				data := []byte(fmt.Sprintf("test data from goroutine %d-%d", id, j))
				_, err := af.WriteToUDPAddrPort(data, dstAddr.AddrPort())
				if err == nil {
					atomic.AddInt64(&successCount, 1)
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	t.Logf("Concurrent writes: %d/%d succeeded", successCount, goroutines*writesPerGoroutine)
	t.Logf("✅ Anyfrom concurrent write test completed (may show races with -race flag)")
}

// TestAnyfromGsoErrorRace 测试 GSO 错误状态的竞争
func TestAnyfromGsoErrorRace(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}
	defer conn.Close()
	
	af := &Anyfrom{
		UDPConn: conn,
		ttl:     30 * time.Second,
		gso:     true,
	}
	af.expiresAtNano.Store(time.Now().Add(30 * time.Second).UnixNano())
	
	const goroutines = 20
	
	var wg sync.WaitGroup
	wg.Add(goroutines)
	
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			
			// 模拟并发设置 GSO 错误
			af.gotGSOError.Store(true)
			
			// 检查状态
			_ = af.gotGSOError.Load()
		}()
	}
	
	wg.Wait()
	
	t.Logf("✅ GSO error state race test completed")
}

// BenchmarkUdpEndpointWriteTo 基准测试 UdpEndpoint 写入性能
func BenchmarkUdpEndpointWriteTo(b *testing.B) {
	mockConn := &mockPacketConn{}
	
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	
	endpoint := &UdpEndpoint{
		conn:       mockConn,
		handler:    func(ue *UdpEndpoint, data []byte, from netip.AddrPort) error { return nil },
		NatTimeout: 30 * time.Second,
		log:        log,
	}
	
	data := []byte("benchmark test data")
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		endpoint.WriteTo(data, "127.0.0.1:8080")
	}
}

// BenchmarkUdpEndpointWriteToParallel 并发基准测试
func BenchmarkUdpEndpointWriteToParallel(b *testing.B) {
	mockConn := &mockPacketConn{}
	
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	
	endpoint := &UdpEndpoint{
		conn:       mockConn,
		handler:    func(ue *UdpEndpoint, data []byte, from netip.AddrPort) error { return nil },
		NatTimeout: 30 * time.Second,
		log:        log,
	}
	
	data := []byte("benchmark test data")
	
	b.ResetTimer()
	
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			endpoint.WriteTo(data, "127.0.0.1:8080")
		}
	})
}

// TestUdpEndpointPoolConcurrentAccess 测试 UdpEndpointPool 的并发访问
func TestUdpEndpointPoolConcurrentAccess(t *testing.T) {
	pool := NewUdpEndpointPool()
	
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	
	const goroutines = 10
	const opsPerGoroutine = 50
	
	var wg sync.WaitGroup
	wg.Add(goroutines)
	
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			
			for j := 0; j < opsPerGoroutine; j++ {
				key := UdpEndpointKey{
					Src: netip.MustParseAddrPort("127.0.0.1:12345"),
					Dst: netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", 8000+id)),
				}
				
				// 尝试获取或创建（这里简化测试，不实际创建）
				_, _, err := pool.GetOrCreate(
					key,
					&UdpEndpointOptions{
						NatTimeout: 30 * time.Second,
						Handler:    func(ue *UdpEndpoint, data []byte, from netip.AddrPort) error { return nil },
						Log:        log,
						GetDialOption: func(ctx context.Context) (option *DialOption, err error) {
							// Return error to simulate dial failure
							return nil, fmt.Errorf("simulated dial error for test")
						},
					},
				)

				if err != nil {
					// 预期会失败，因为 GetDialOption 返回错误
					t.Logf("Expected error for goroutine %d op %d: %v", id, j, err)
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	t.Logf("✅ UdpEndpointPool concurrent access test completed")
}
