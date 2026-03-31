package shadowsocks

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

// mockShadowsocksPacketConn 模拟 Shadowsocks PacketConn
type mockShadowsocksPacketConn struct {
	writes int64
}

func (m *mockShadowsocksPacketConn) Read(b []byte) (n int, err error) {
	return 0, nil
}

func (m *mockShadowsocksPacketConn) Write(b []byte) (n int, err error) {
	atomic.AddInt64(&m.writes, 1)
	time.Sleep(10 * time.Microsecond) // 模拟延迟
	return len(b), nil
}

func (m *mockShadowsocksPacketConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	return 0, netip.AddrPort{}, nil
}

func (m *mockShadowsocksPacketConn) WriteTo(p []byte, addr string) (n int, err error) {
	atomic.AddInt64(&m.writes, 1)
	time.Sleep(10 * time.Microsecond) // 模拟延迟
	return len(p), nil
}

func (m *mockShadowsocksPacketConn) Close() error {
	return nil
}

func (m *mockShadowsocksPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockShadowsocksPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockShadowsocksPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// TestShadowsocksUdpConnWriteToRace 测试并发写入竞争
// 运行: go test -race -run TestShadowsocksUdpConnWriteToRace
func TestShadowsocksUdpConnWriteToRace(t *testing.T) {
	// 创建 mock 连接
	mockConn := &mockShadowsocksPacketConn{}
	
	// 创建 UdpConn
	conf := ciphers.AeadCiphersConf["aes-128-gcm"]
	masterKey := make([]byte, 16)
	
	metadata := protocol.Metadata{
		Type:     protocol.MetadataTypeIPv4,
		Hostname: "127.0.0.1",
		Port:     8080,
		Cipher:   "aes-128-gcm",
	}
	
	udpConn := &UdpConn{
		PacketConn:   mockConn,
		proxyAddress: "127.0.0.1:8388",
		metadata:     metadata,
		cipherConf:   conf,
		masterKey:    masterKey,
		tgtAddr:      "127.0.0.1:8080",
	}
	
	const goroutines = 10
	const writesPerGoroutine = 50 // 减少次数因为加密开销大
	
	var wg sync.WaitGroup
	wg.Add(goroutines)
	
	// 启动多个 goroutine 并发写入
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			
			for j := 0; j < writesPerGoroutine; j++ {
				data := []byte("test data from goroutine")
				_, err := udpConn.WriteTo(data, "127.0.0.1:9090")
				if err != nil {
					// 加密失败是预期的，因为我们没有完整初始化
					t.Logf("Goroutine %d write %d: %v (expected)", id, j, err)
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	// 验证写入次数
	writes := atomic.LoadInt64(&mockConn.writes)
	t.Logf("Total WriteTo calls: %d", writes)
	
	// 注意：由于加密可能失败，实际写入次数可能少于预期
	// 这个测试主要检测 -race 是否报告竞争
}

// TestShadowsocksUdpConnWriteRace 测试 Write 方法的并发
func TestShadowsocksUdpConnWriteRace(t *testing.T) {
	mockConn := &mockShadowsocksPacketConn{}
	
	conf := ciphers.AeadCiphersConf["aes-128-gcm"]
	masterKey := make([]byte, 16)
	
	metadata := protocol.Metadata{
		Type:     protocol.MetadataTypeIPv4,
		Hostname: "127.0.0.1",
		Port:     8080,
		Cipher:   "aes-128-gcm",
	}
	
	udpConn := &UdpConn{
		PacketConn:   mockConn,
		proxyAddress: "127.0.0.1:8388",
		metadata:     metadata,
		cipherConf:   conf,
		masterKey:    masterKey,
		tgtAddr:      "127.0.0.1:8080",
	}
	
	const goroutines = 10
	const writesPerGoroutine = 50
	
	var wg sync.WaitGroup
	wg.Add(goroutines)
	
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			
			for j := 0; j < writesPerGoroutine; j++ {
				data := []byte("test data")
				_, err := udpConn.Write(data)
				if err != nil {
					t.Logf("Goroutine %d write %d: %v", id, j, err)
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	t.Logf("Completed concurrent Write test")
}

// TestShadowsocksUdpConnBufferPoolRace 测试 buffer pool 的并发使用
func TestShadowsocksUdpConnBufferPoolRace(t *testing.T) {
	// 测试 pool.Get 和 pool.Put 的并发使用
	const goroutines = 20
	const opsPerGoroutine = 100
	
	var wg sync.WaitGroup
	wg.Add(goroutines)
	
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			
			for j := 0; j < opsPerGoroutine; j++ {
				buf := pool.Get(1500)
				
				// 模拟使用 buffer
				copy(buf, []byte("test data"))
				
				// 释放 buffer
				pool.Put(buf)
			}
		}(i)
	}
	
	wg.Wait()
	
	t.Log("Buffer pool concurrent access test completed")
}

// TestShadowsocksUdpConnRealConnection 使用真实 UDP 连接测试
func TestShadowsocksUdpConnRealConnection(t *testing.T) {
	// 创建 UDP 服务器
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve server address: %v", err)
	}
	
	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer func() { _ = serverConn.Close() }()
	
	// 接收服务器
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			t.Logf("Server received %d bytes from %v", n, addr)
		}
	}()
	
	// 创建客户端连接
	clientConn, err := net.Dial("udp", serverConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = clientConn.Close() }()
	
	// 包装为 netproxy.PacketConn（需要实现）
	t.Skip("Requires netproxy.PacketConn implementation")
}

// BenchmarkShadowsocksUdpConnWrite 基准测试
func BenchmarkShadowsocksUdpConnWrite(b *testing.B) {
	mockConn := &mockShadowsocksPacketConn{}
	
	conf := ciphers.AeadCiphersConf["aes-128-gcm"]
	masterKey := make([]byte, 16)
	
	metadata := protocol.Metadata{
		Type:     protocol.MetadataTypeIPv4,
		Hostname: "127.0.0.1",
		Port:     8080,
		Cipher:   "aes-128-gcm",
	}
	
	udpConn := &UdpConn{
		PacketConn:   mockConn,
		proxyAddress: "127.0.0.1:8388",
		metadata:     metadata,
		cipherConf:   conf,
		masterKey:    masterKey,
		tgtAddr:      "127.0.0.1:8080",
	}
	
	data := []byte("benchmark test data")
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, _ = udpConn.Write(data)
	}
}

// BenchmarkShadowsocksUdpConnWriteParallel 并发基准测试
func BenchmarkShadowsocksUdpConnWriteParallel(b *testing.B) {
	mockConn := &mockShadowsocksPacketConn{}
	
	conf := ciphers.AeadCiphersConf["aes-128-gcm"]
	masterKey := make([]byte, 16)
	
	metadata := protocol.Metadata{
		Type:     protocol.MetadataTypeIPv4,
		Hostname: "127.0.0.1",
		Port:     8080,
		Cipher:   "aes-128-gcm",
	}
	
	udpConn := &UdpConn{
		PacketConn:   mockConn,
		proxyAddress: "127.0.0.1:8388",
		metadata:     metadata,
		cipherConf:   conf,
		masterKey:    masterKey,
		tgtAddr:      "127.0.0.1:8080",
	}
	
	data := []byte("benchmark test data")
	
	b.ResetTimer()
	
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = udpConn.Write(data)
		}
	})
}

// TestShadowsocksUdpConnMetadataParseRace 测试 metadata 解析的并发安全
func TestShadowsocksUdpConnMetadataParseRace(t *testing.T) {
	const goroutines = 20
	const opsPerGoroutine = 100
	
	var wg sync.WaitGroup
	wg.Add(goroutines)
	
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			
			for j := 0; j < opsPerGoroutine; j++ {
				addr := "127.0.0.1:8080"
				_, err := protocol.ParseMetadata(addr)
				if err != nil {
					t.Errorf("Goroutine %d parse %d failed: %v", id, j, err)
				}
			}
		}(i)
	}
	
	wg.Wait()
}
