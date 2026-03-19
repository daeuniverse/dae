package control

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type writeTrackingPacketConn struct {
	activeWrites atomic.Int32
	maxWrites    atomic.Int32
	writeCalls   atomic.Int32
	shortWrite   bool

	writeDelay time.Duration
}

func (c *writeTrackingPacketConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *writeTrackingPacketConn) Write(b []byte) (int, error) { return len(b), nil }

func (c *writeTrackingPacketConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}

func (c *writeTrackingPacketConn) WriteTo(b []byte, _ string) (int, error) {
	active := c.activeWrites.Add(1)
	defer c.activeWrites.Add(-1)
	c.writeCalls.Add(1)
	for {
		maxSeen := c.maxWrites.Load()
		if active <= maxSeen {
			break
		}
		if c.maxWrites.CompareAndSwap(maxSeen, active) {
			break
		}
	}
	if c.writeDelay > 0 {
		time.Sleep(c.writeDelay)
	}
	if c.shortWrite && len(b) > 0 {
		return len(b) - 1, nil
	}
	return len(b), nil
}

func (c *writeTrackingPacketConn) Close() error                     { return nil }
func (c *writeTrackingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *writeTrackingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *writeTrackingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestUdpEndpointWriteTo_AllowsConcurrentWrites(t *testing.T) {
	conn := &writeTrackingPacketConn{writeDelay: 2 * time.Millisecond}
	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: time.Minute,
	}

	var wg sync.WaitGroup
	var writeErr error
	var mu sync.Mutex
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ue.WriteTo([]byte("payload"), "198.51.100.10:3478")
			mu.Lock()
			defer mu.Unlock()
			if err != nil && writeErr == nil {
				writeErr = err
			}
		}()
	}
	wg.Wait()
	require.NoError(t, writeErr)

	require.Equal(t, int32(32), conn.writeCalls.Load(), "all writes should complete")
	// With the write lock removed, concurrent writes are allowed for better performance.
	// The mock connection tracks concurrent writes via activeWrites/maxWrites atomics.
	// We verify thread-safety by ensuring all writes complete without data races.
	maxSeen := conn.maxWrites.Load()
	require.Greater(t, maxSeen, int32(1), "expected concurrent writes (no serialization)")
	t.Logf("✅ Thread-safe concurrent writes verified: %d max concurrent writes out of 32 total", maxSeen)
}

func TestUdpEndpointWriteTo_TreatsShortWriteAsError(t *testing.T) {
	ue := &UdpEndpoint{
		conn:       &writeTrackingPacketConn{shortWrite: true},
		NatTimeout: time.Minute,
	}

	n, err := ue.WriteTo([]byte("payload"), "198.51.100.10:3478")
	require.ErrorIs(t, err, io.ErrShortWrite)
	require.Equal(t, len("payload")-1, n)
	// A short write must mark the endpoint dead so queued writers fail fast.
	require.True(t, ue.IsDead(), "short write should mark endpoint dead")
}

func TestUdpEndpointWriteTo_FailsFastWhenAlreadyDead(t *testing.T) {
	conn := &writeTrackingPacketConn{}
	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: time.Minute,
	}
	ue.dead.Store(true)

	_, err := ue.WriteTo([]byte("payload"), "198.51.100.10:3478")
	require.ErrorIs(t, err, net.ErrClosed, "write to dead endpoint should return net.ErrClosed")
	require.Equal(t, int32(0), conn.writeCalls.Load(), "conn.WriteTo must not be called for a dead endpoint")
}

func TestUdpEndpointWriteTo_MarksDead_OnWriteError(t *testing.T) {
	failConn := &failingPacketConn{}
	ue := &UdpEndpoint{
		conn:       failConn,
		NatTimeout: time.Minute,
	}

	_, err := ue.WriteTo([]byte("payload"), "198.51.100.10:3478")
	require.Error(t, err)
	require.True(t, ue.IsDead(), "write error should mark endpoint dead")

	// A subsequent write must short-circuit without touching the conn.
	_, err2 := ue.WriteTo([]byte("more"), "198.51.100.10:3478")
	require.ErrorIs(t, err2, net.ErrClosed)
	require.Equal(t, 1, failConn.calls, "conn.WriteTo must be called exactly once (pre-dead-check fast path on second call)")
}

// failingPacketConn always returns a write error.
type failingPacketConn struct{ calls int }

func (c *failingPacketConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *failingPacketConn) Write(b []byte) (int, error) { return 0, io.ErrClosedPipe }
func (c *failingPacketConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (c *failingPacketConn) WriteTo(b []byte, _ string) (int, error) {
	c.calls++
	return 0, io.ErrClosedPipe
}
func (c *failingPacketConn) Close() error                     { return nil }
func (c *failingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *failingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *failingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestUdpEndpoint_SelfRemovesFromPool_OnReadLoopExit(t *testing.T) {
	p := NewUdpEndpointPool()
	key := UdpEndpointKey{Src: netip.MustParseAddrPort("127.0.0.1:12345")}

	bc := &blockingConn{unblock: make(chan struct{})}
	ue := &UdpEndpoint{
		conn:       bc,
		NatTimeout: time.Minute,
		handler:    func(*UdpEndpoint, []byte, netip.AddrPort) error { return nil },
		poolRef:    p,
		poolKey:    key,
	}
	ue.RefreshTtl()
	p.pool.Store(key, ue)
	go ue.start()

	// Endpoint must be present before we trigger the read loop exit.
	_, ok := p.pool.Load(key)
	require.True(t, ok, "endpoint should be in pool before read loop exits")

	// Signal read loop to return error (simulates remote close).
	close(bc.unblock)

	require.Eventually(t, func() bool {
		_, ok := p.pool.Load(key)
		return !ok
	}, time.Second, time.Millisecond,
		"dead endpoint should self-remove from pool within 1s")
	require.True(t, ue.IsDead())
}

func TestUdpEndpointResponseConnCacheSlot_FullConeReturnsNil(t *testing.T) {
	ue := &UdpEndpoint{
		poolKey:    UdpEndpointKey{Src: netip.MustParseAddrPort("127.0.0.1:12345")},
		respConn:   &Anyfrom{},
		NatTimeout: time.Minute,
	}

	require.Nil(t, ue.responseConnCacheSlot(), "full-cone endpoint must not expose respConn cache slot")
}

func TestUdpEndpointResponseConnCacheSlot_SymmetricReturnsRespConnPointer(t *testing.T) {
	cached := &Anyfrom{}
	ue := &UdpEndpoint{
		poolKey: UdpEndpointKey{
			Src: netip.MustParseAddrPort("127.0.0.1:12345"),
			Dst: netip.MustParseAddrPort("198.51.100.10:3478"),
		},
		respConn: cached,
	}

	slot := ue.responseConnCacheSlot()
	if slot == nil {
		t.Fatal("symmetric endpoint should expose respConn cache slot")
	}
	require.Same(t, cached, *slot)
	replacement := &Anyfrom{}
	*slot = replacement
	require.Same(t, replacement, ue.respConn)
}

// blockingConn blocks ReadFrom until unblock is closed, then returns io.EOF.
type blockingConn struct {
	writeTrackingPacketConn
	unblock chan struct{}
}

func (c *blockingConn) ReadFrom(_ []byte) (int, netip.AddrPort, error) {
	<-c.unblock
	return 0, netip.AddrPort{}, io.EOF
}
