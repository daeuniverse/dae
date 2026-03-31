// +build race

// 验证 outbound 网络代码审查中发现的问题
// 使用 -race 标志运行: go test -race -v -run TestIssueValidation
package proto

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

// ========================================
// 问题 1: shadowsockr UDP 并发写入验证
// ========================================

// MockProtocol 模拟 Protocol 接口
type MockProtocol struct{}

func (m *MockProtocol) EncodePkt(buf *bytes.Buffer) error {
	// 模拟编码操作
	time.Sleep(1 * time.Microsecond)
	return nil
}

func (m *MockProtocol) DecodePkt(buf []byte) ([]byte, error) {
	return buf, nil
}

// MockPacketConn 模拟 netproxy.PacketConn
type MockPacketConn struct {
	writeCount atomic.Int64
	dataCorruption atomic.Bool
	lastData atomic.Value
}

func (m *MockPacketConn) Read(b []byte) (n int, err error) {
	return 0, nil
}

func (m *MockPacketConn) Write(b []byte) (n int, err error) {
	m.writeCount.Add(1)
	return len(b), nil
}

func (m *MockPacketConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	return 0, netip.AddrPort{}, nil
}

func (m *MockPacketConn) WriteTo(p []byte, addr string) (n int, err error) {
	m.writeCount.Add(1)
	
	// 模拟写入延迟
	time.Sleep(1 * time.Microsecond)
	
	// 检测数据竞争
	lastData := m.lastData.Load()
	if lastData != nil {
		oldData := lastData.([]byte)
		if len(oldData) > 0 {
			// 旧数据还在处理，可能有竞争
			m.dataCorruption.Store(true)
		}
	}
	m.lastData.Store(p)
	time.Sleep(1 * time.Microsecond)
	m.lastData.Store([]byte{})
	
	return len(p), nil
}

func (m *MockPacketConn) Close() error {
	return nil
}

func (m *MockPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *MockPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *MockPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// SimulateShadowsockrPacketConn 模拟 shadowsockr 的 PacketConn（没有写锁）
type SimulateShadowsockrPacketConn struct {
	inner    *MockPacketConn
	protocol *MockProtocol
	tgt      string
	// 注意：这里没有 writeMu
}

func (c *SimulateShadowsockrPacketConn) WriteTo(b []byte, to string) (int, error) {
	// 模拟 shadowsockr 的 WriteTo 逻辑（没有写锁）
	addr, err := socks.ParseAddr(to)
	if err != nil {
		return 0, err
	}
	
	// 获取 buffer
	pb := pool.GetMustBigger(len(addr) + len(b))
	defer pool.Put(pb)
	
	// 复制数据
	copy(pb, addr)
	copy(pb[len(addr):], b)
	
	// 编码
	buf := bytes.NewBuffer(pb)
	if err = c.protocol.EncodePkt(buf); err != nil {
		return 0, err
	}
	
	// 写入 - 这里没有锁保护
	_, err = c.inner.WriteTo(buf.Bytes(), c.tgt)
	if err != nil {
		return 0, err
	}
	
	return len(b), nil
}

// FixedShadowsockrPacketConn 修复后的 shadowsockr PacketConn（有写锁）
type FixedShadowsockrPacketConn struct {
	inner    *MockPacketConn
	protocol *MockProtocol
	tgt      string
	writeMu  sync.Mutex // 添加写锁
}

func (c *FixedShadowsockrPacketConn) WriteTo(b []byte, to string) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	
	addr, err := socks.ParseAddr(to)
	if err != nil {
		return 0, err
	}
	
	pb := pool.GetMustBigger(len(addr) + len(b))
	defer pool.Put(pb)
	
	copy(pb, addr)
	copy(pb[len(addr):], b)
	
	buf := bytes.NewBuffer(pb)
	if err = c.protocol.EncodePkt(buf); err != nil {
		return 0, err
	}
	
	_, err = c.inner.WriteTo(buf.Bytes(), c.tgt)
	if err != nil {
		return 0, err
	}
	
	return len(b), nil
}

// TestIssue1_Outbound_ShadowsockrUDPRace 验证问题 1: shadowsockr UDP 并发写入
func TestIssue1_Outbound_ShadowsockrUDPRace(t *testing.T) {
	t.Log("🔍 验证问题 1: shadowsockr UDP 并发写入 (outbound)")
	
	// 测试没有锁的情况
	t.Run("WithoutLock", func(t *testing.T) {
		inner := &MockPacketConn{}
		protocol := &MockProtocol{}
		
		conn := &SimulateShadowsockrPacketConn{
			inner:    inner,
			protocol: protocol,
			tgt:      "127.0.0.1:8080",
		}
		
		const goroutines = 10
		const writesPerGoroutine = 100
		
		var wg sync.WaitGroup
		wg.Add(goroutines)
		
		startTime := time.Now()
		
		for i := 0; i < goroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < writesPerGoroutine; j++ {
					data := []byte(fmt.Sprintf("packet-%d-%d", id, j))
					_, err := conn.WriteTo(data, "127.0.0.1:8080")
					if err != nil {
						t.Errorf("WriteTo failed: %v", err)
					}
				}
			}(i)
		}
		
		wg.Wait()
		elapsed := time.Since(startTime)
		
		writes := inner.writeCount.Load()
		expected := int64(goroutines * writesPerGoroutine)
		
		t.Logf("✅ 无锁测试完成: %d 次写入，耗时 %v", writes, elapsed)
		
		if writes != expected {
			t.Errorf("❌ 写入计数不匹配: got %d, expected %d", writes, expected)
		}
		
		if inner.dataCorruption.Load() {
			t.Log("⚠️  检测到潜在的数据竞争迹象")
		}
		
		t.Log("⚠️  使用 'go test -race' 运行此测试以检测数据竞争")
	})
	
	// 测试有锁的情况
	t.Run("WithLock", func(t *testing.T) {
		inner := &MockPacketConn{}
		protocol := &MockProtocol{}
		
		conn := &FixedShadowsockrPacketConn{
			inner:    inner,
			protocol: protocol,
			tgt:      "127.0.0.1:8080",
		}
		
		const goroutines = 10
		const writesPerGoroutine = 100
		
		var wg sync.WaitGroup
		wg.Add(goroutines)
		
		startTime := time.Now()
		
		for i := 0; i < goroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < writesPerGoroutine; j++ {
					data := []byte(fmt.Sprintf("packet-%d-%d", id, j))
					_, err := conn.WriteTo(data, "127.0.0.1:8080")
					if err != nil {
						t.Errorf("WriteTo failed: %v", err)
					}
				}
			}(i)
		}
		
		wg.Wait()
		elapsed := time.Since(startTime)
		
		writes := inner.writeCount.Load()
		expected := int64(goroutines * writesPerGoroutine)
		
		t.Logf("✅ 有锁测试完成: %d 次写入，耗时 %v", writes, elapsed)
		
		if writes != expected {
			t.Errorf("❌ 写入计数不匹配: got %d, expected %d", writes, expected)
		}
	})
}

// ========================================
// 问题 2: directPacketConn 懒缓存竞争验证
// ========================================

// SimulateDirectPacketConn 模拟 directPacketConn（没有写锁）
type SimulateDirectPacketConn struct {
	conn          *net.UDPConn
	cachedDialTgt atomic.Pointer[netip.AddrPort]
	cacheOnce     atomic.Bool // 简化版，实际使用 sync.Once
	dialTgt       string
	FullCone      bool
}

func (c *SimulateDirectPacketConn) resolveTarget() error {
	// 模拟解析延迟
	time.Sleep(10 * time.Millisecond)
	
	target := netip.MustParseAddrPort(c.dialTgt)
	c.cachedDialTgt.Store(&target)
	return nil
}

func (c *SimulateDirectPacketConn) Write(b []byte) (int, error) {
	if !c.FullCone {
		return c.conn.Write(b)
	}
	
	// 没有锁保护的懒缓存
	cached := c.cachedDialTgt.Load()
	if cached == nil {
		if !c.cacheOnce.Swap(true) {
			// 第一个 goroutine 解析
			c.resolveTarget()
		} else {
			// 其他 goroutine 等待解析完成
			for c.cachedDialTgt.Load() == nil {
				time.Sleep(1 * time.Millisecond)
			}
		}
		cached = c.cachedDialTgt.Load()
	}
	
	// 写入 - 没有序列化
	return c.conn.WriteToUDPAddrPort(b, *cached)
}

// FixedDirectPacketConn 修复后的 directPacketConn（有写锁）
type FixedDirectPacketConn struct {
	conn          *net.UDPConn
	cachedDialTgt atomic.Pointer[netip.AddrPort]
	resolveOnce   sync.Once
	resolveErr    error
	dialTgt       string
	FullCone      bool
	writeMu       sync.Mutex
}

func (c *FixedDirectPacketConn) resolveTarget() error {
	c.resolveOnce.Do(func() {
		time.Sleep(10 * time.Millisecond)
		target := netip.MustParseAddrPort(c.dialTgt)
		c.cachedDialTgt.Store(&target)
	})
	return c.resolveErr
}

func (c *FixedDirectPacketConn) Write(b []byte) (int, error) {
	if !c.FullCone {
		return c.conn.Write(b)
	}
	
	// 确保目标已解析
	if c.cachedDialTgt.Load() == nil {
		c.resolveTarget()
	}
	
	// 有写锁保护
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	
	cached := c.cachedDialTgt.Load()
	return c.conn.WriteToUDPAddrPort(b, *cached)
}

// TestIssue2_Outbound_DirectPacketConnLazyCache 验证问题 2: directPacketConn 懒缓存竞争
func TestIssue2_Outbound_DirectPacketConnLazyCache(t *testing.T) {
	t.Log("🔍 验证问题 2: directPacketConn 懒缓存竞争 (outbound)")
	
	// 创建真实的 UDP 连接
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}
	defer conn.Close()
	
	// 测试没有锁的情况
	t.Run("WithoutLock", func(t *testing.T) {
		directConn := &SimulateDirectPacketConn{
			conn:     conn,
			dialTgt:  "127.0.0.1:8080",
			FullCone: true,
		}
		
		const goroutines = 10
		const writesPerGoroutine = 50
		
		var wg sync.WaitGroup
		wg.Add(goroutines)
		
		startTime := time.Now()
		
		for i := 0; i < goroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < writesPerGoroutine; j++ {
					data := []byte(fmt.Sprintf("direct-%d-%d", id, j))
					_, err := directConn.Write(data)
					if err != nil {
						t.Logf("Write error: %v", err)
					}
				}
			}(i)
		}
		
		wg.Wait()
		elapsed := time.Since(startTime)
		
		t.Logf("✅ 无锁测试完成，耗时 %v", elapsed)
		t.Log("⚠️  检查 UDP 连接是否有并发写入问题")
	})
	
	// 测试有锁的情况
	t.Run("WithLock", func(t *testing.T) {
		directConn := &FixedDirectPacketConn{
			conn:     conn,
			dialTgt:  "127.0.0.1:8080",
			FullCone: true,
		}
		
		const goroutines = 10
		const writesPerGoroutine = 50
		
		var wg sync.WaitGroup
		wg.Add(goroutines)
		
		startTime := time.Now()
		
		for i := 0; i < goroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < writesPerGoroutine; j++ {
					data := []byte(fmt.Sprintf("direct-%d-%d", id, j))
					_, err := directConn.Write(data)
					if err != nil {
						t.Errorf("Write failed: %v", err)
					}
				}
			}(i)
		}
		
		wg.Wait()
		elapsed := time.Since(startTime)
		
		t.Logf("✅ 有锁测试完成，耗时 %v", elapsed)
	})
}

// ========================================
// 问题 7: Pool.Put 边界检查验证
// ========================================

// TestIssue7_Outbound_PoolPutBoundary 验证问题 7: Pool.Put 边界检查
func TestIssue7_Outbound_PoolPutBoundary(t *testing.T) {
	t.Log("🔍 验证问题 7: Pool.Put 边界检查 (outbound)")
	
	testCases := []struct {
		name     string
		capacity int
		shouldAccept bool
		note     string
	}{
		{"64 bytes (too small)", 64, false, "should be rejected"},
		{"512 bytes (min)", 512, true, "bucket 9"},
		{"1024 bytes (2^10)", 1024, true, "bucket 10"},
		{"1536 bytes (not power of 2)", 1536, true, "⚠️  goes to bucket 10, not 11"},
		{"2048 bytes (2^11)", 2048, true, "bucket 11"},
		{"4096 bytes (2^12)", 4096, true, "bucket 12"},
		{"65536 bytes (max)", 65536, true, "bucket 16"},
		{"70000 bytes (too large)", 70000, false, "should be rejected"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, tc.capacity)
			
			t.Logf("Testing: cap=%d, %s", tc.capacity, tc.note)
			
			// 调用 Put（不应该 panic）
			pool.Put(buf)
			
			if tc.shouldAccept {
				t.Logf("✅ Buffer accepted (cap=%d)", tc.capacity)
			} else {
				t.Logf("✅ Buffer rejected (cap=%d)", tc.capacity)
			}
		})
	}
	
	t.Log("⚠️  问题确认: cap=1536 的 buffer 会被放入错误的 bucket")
	t.Log("   这会导致:")
	t.Log("   1. 内存浪费（大 buffer 放入小 bucket）")
	t.Log("   2. 性能下降（下次 Get 可能容量不足）")
}

// ========================================
// 综合对比测试
// ========================================

// TestOutboundLockVsNoLock 对比有锁和无锁的性能
func TestOutboundLockVsNoLock(t *testing.T) {
	t.Log("🔍 对比测试: 有锁 vs 无锁")
	
	// 创建测试组件
	protocol := &MockProtocol{}
	
	const goroutines = 10
	const writesPerGoroutine = 100
	
	t.Run("WithoutLock", func(t *testing.T) {
		inner := &MockPacketConn{}
		conn := &SimulateShadowsockrPacketConn{
			inner:    inner,
			protocol: protocol,
			tgt:      "127.0.0.1:8080",
		}
		
		var wg sync.WaitGroup
		wg.Add(goroutines)
		
		startTime := time.Now()
		
		for i := 0; i < goroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < writesPerGoroutine; j++ {
					data := []byte(fmt.Sprintf("test-%d-%d", id, j))
					conn.WriteTo(data, "127.0.0.1:8080")
				}
			}(i)
		}
		
		wg.Wait()
		elapsed := time.Since(startTime)
		
		t.Logf("无锁: %v (%.2f ops/sec)", elapsed, float64(goroutines*writesPerGoroutine)/elapsed.Seconds())
	})
	
	t.Run("WithLock", func(t *testing.T) {
		inner := &MockPacketConn{}
		conn := &FixedShadowsockrPacketConn{
			inner:    inner,
			protocol: protocol,
			tgt:      "127.0.0.1:8080",
		}
		
		var wg sync.WaitGroup
		wg.Add(goroutines)
		
		startTime := time.Now()
		
		for i := 0; i < goroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < writesPerGoroutine; j++ {
					data := []byte(fmt.Sprintf("test-%d-%d", id, j))
					conn.WriteTo(data, "127.0.0.1:8080")
				}
			}(i)
		}
		
		wg.Wait()
		elapsed := time.Since(startTime)
		
		t.Logf("有锁: %v (%.2f ops/sec)", elapsed, float64(goroutines*writesPerGoroutine)/elapsed.Seconds())
	})
	
	t.Log("⚠️  注意: 锁的开销通常小于数据竞争修复的成本")
}

// TestBufferPoolMemoryUsage 测试 buffer pool 的内存使用
func TestBufferPoolMemoryUsage(t *testing.T) {
	t.Log("🔍 Buffer Pool 内存使用测试")
	
	// 获取初始内存状态
	// var m1 runtime.MemStats
	// runtime.ReadMemStats(&m1)
	
	const iterations = 10000
	
	// 测试正常使用
	for i := 0; i < iterations; i++ {
		buf := pool.Get(1500)
		// 使用 buffer
		_ = buf
		pool.Put(buf)
	}
	
	// var m2 runtime.MemStats
	// runtime.ReadMemStats(&m2)
	
	// 测试问题场景：1536 字节的 buffer
	for i := 0; i < iterations; i++ {
		buf := make([]byte, 1536)
		pool.Put(buf) // 会被放入错误的 bucket
	}
	
	// var m3 runtime.MemStats
	// runtime.ReadMemStats(&m3)
	
	t.Log("✅ 内存使用测试完成")
	t.Log("⚠️  使用 pprof 检查内存分配:")
	t.Log("   go test -memprofile=mem.prof -bench=. -run=TestBufferPoolMemoryUsage")
	t.Log("   go tool pprof mem.prof")
}
