/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// receiverConn is a fake PacketConn whose transport-owned receiver hands the
// registered handler directly to the test, mimicking push-mode delivery from
// a QUIC session reader or the direct protocol's shared epoll loop.
type receiverConn struct {
	mu                   sync.Mutex
	handler              netproxy.PacketReceiveHandler
	stops                int
	readonly             atomic.Int64 // deliver calls observed after unregister
	deliverOnRegister    bool
	deliverErrOnRegister error

	closed atomic.Bool
}

func (c *receiverConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	if handler == nil {
		return nil, false
	}
	c.mu.Lock()
	if c.handler != nil {
		c.mu.Unlock()
		return nil, false
	}
	c.handler = handler
	deliverOnRegister := c.deliverOnRegister
	errOnRegister := c.deliverErrOnRegister
	var once sync.Once
	stop := func() {
		once.Do(func() {
			c.mu.Lock()
			c.handler = nil
			c.stops++
			c.mu.Unlock()
		})
	}
	c.mu.Unlock()
	if errOnRegister != nil {
		_ = handler(netproxy.NewReceivedPacket(nil, receiverTestFrom(), errOnRegister, func() {}))
	} else if deliverOnRegister {
		_ = handler(netproxy.NewReceivedPacket(
			[]byte("sync-register"),
			receiverTestFrom(),
			nil,
			func() {},
		))
	}
	return stop, true
}

func (c *receiverConn) deliver(seq int) bool {
	data := fmt.Appendf(nil, "packet-%04d", seq)
	packet := netproxy.NewReceivedPacket(data, receiverTestFrom(), nil, func() {})
	c.mu.Lock()
	handler := c.handler
	c.mu.Unlock()
	if handler == nil {
		c.readonly.Add(1)
		return false
	}
	return handler(packet)
}

func (c *receiverConn) registered() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.handler != nil
}

func (c *receiverConn) unregisterCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stops
}

func (c *receiverConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *receiverConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *receiverConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (c *receiverConn) WriteTo(p []byte, _ string) (int, error) { return len(p), nil }
func (c *receiverConn) Close() error {
	c.closed.Store(true)
	return nil
}
func (c *receiverConn) SetDeadline(time.Time) error      { return nil }
func (c *receiverConn) SetReadDeadline(time.Time) error  { return nil }
func (c *receiverConn) SetWriteDeadline(time.Time) error { return nil }

func receiverTestFrom() netip.AddrPort {
	return netip.MustParseAddrPort("203.0.113.7:4500")
}

// newReceiverTestEndpoint builds a minimal endpoint wired for push mode.
// poolKey.Dst matches the delivery source so the initial-reply guard
// accepts the first packet, exactly as a real dialed endpoint would.
func newReceiverTestEndpoint(t *testing.T, conn *receiverConn, handler UdpHandler) *UdpEndpoint {
	t.Helper()
	log := logrus.New()
	log.SetOutput(io.Discard)
	ue := &UdpEndpoint{
		conn:    conn,
		handler: handler,
		log:     log,
		poolKey: UdpEndpointKey{Dst: receiverTestFrom()},
	}
	require.True(t, ue.startTransportReceiver(), "fake receiver conn failed to register")
	return ue
}

// TestPacketReceiverPreservesReplyFIFO asserts push-mode deliveries reach the
// handler in submission order through the bounded queue and sender goroutine.
func TestPacketReceiverPreservesReplyFIFO(t *testing.T) {
	conn := &receiverConn{}
	var mu sync.Mutex
	var got []string
	ue := newReceiverTestEndpoint(t, conn, func(_ *UdpEndpoint, data []byte, _ netip.AddrPort) error {
		mu.Lock()
		got = append(got, string(data))
		mu.Unlock()
		return nil
	})

	const total = 64
	for i := range total {
		require.True(t, conn.deliver(i), "delivery %d rejected while registered", i)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == total {
			break
		}
		require.Less(t, time.Now(), deadline, "handler observed %d of %d replies", n, total)
		time.Sleep(2 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	for i := range total {
		require.Equal(t, fmt.Sprintf("packet-%04d", i), got[i], "reply %d out of order", i)
	}
	require.True(t, conn.registered(), "receiver unregistered during healthy delivery")
	require.NoError(t, ue.Close())
	require.Equal(t, 1, conn.unregisterCount(), "Close must unregister the receiver exactly once")
}

// TestPacketReceiverFullQueueDropsCurrentPacket blocks the handler, overflows
// the bounded queue, and asserts only the excess packets are dropped while
// the receiver stays registered and the survivors stay ordered.
func TestPacketReceiverFullQueueDropsCurrentPacket(t *testing.T) {
	conn := &receiverConn{}
	var handled atomic.Int64
	release := make(chan struct{})
	ue := newReceiverTestEndpoint(t, conn, func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error {
		handled.Add(1)
		<-release
		return nil
	})

	const total = udpEndpointReplyQueueSize + 64
	for i := range total {
		// Deliveries that find the queue full return true: the packet is
		// dropped but the receiver must stay registered.
		conn.deliver(i)
	}
	require.True(t, conn.registered(), "full queue must not unregister the receiver")
	close(release)
	// Close drains every accepted reply, so once it returns the handled count
	// is final: at least the queue capacity was accepted (the queue filled),
	// and strictly less than the total was accepted (the overflow dropped).
	require.NoError(t, ue.Close())
	accepted := handled.Load()
	require.GreaterOrEqual(t, accepted, int64(udpEndpointReplyQueueSize),
		"queue must have filled before dropping")
	require.Less(t, accepted, int64(total),
		"overflow packets must be dropped rather than accepted")
}

// TestPacketReceiverCloseDrainsQueuedReplies enqueues replies behind a gated
// handler, closes the endpoint, and asserts Close waits for the sender to
// finish the already-accepted work instead of leaking or losing it silently.
func TestPacketReceiverCloseDrainsQueuedReplies(t *testing.T) {
	conn := &receiverConn{}
	var handled atomic.Int64
	gate := make(chan struct{})
	ue := newReceiverTestEndpoint(t, conn, func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error {
		n := handled.Add(1)
		if n <= 2 {
			<-gate
		}
		return nil
	})

	for i := range 16 {
		require.True(t, conn.deliver(i))
	}

	closed := make(chan error, 1)
	go func() { closed <- ue.Close() }()
	// The sender is parked on the gated handler; Close must not return before
	// unblocking it would strand queued replies. Give the drain a moment to
	// prove Close is waiting, then open the gate.
	select {
	case err := <-closed:
		t.Fatalf("Close returned %v while the sender was still draining", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(gate)
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return after the sender drained")
	}
	require.Equal(t, int64(16), handled.Load(), "Close must let every accepted reply run")
	require.Equal(t, 1, conn.unregisterCount())
}

// TestPacketReceiverDeadEndpointRejectsAndReleases verifies the dead check:
// after Close, a racing delivery releases its packet and reports false so the
// transport unregisters.
func TestPacketReceiverDeadEndpointRejectsAndReleases(t *testing.T) {
	conn := &receiverConn{}
	ue := newReceiverTestEndpoint(t, conn, func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error {
		return nil
	})
	require.NoError(t, ue.Close())

	released := atomic.Bool{}
	packet := netproxy.NewReceivedPacket([]byte("late"), receiverTestFrom(), nil, func() {
		released.Store(true)
	})
	// Bypass conn.deliver: its handler is already unregistered, so invoke the
	// endpoint callback directly as an in-flight racing delivery would.
	require.False(t, ue.handleReceivedPacket(packet), "dead endpoint must reject deliveries")
	require.True(t, released.Load(), "rejected delivery must release its packet")
}

// TestPacketReceiverHandlerErrorDoesNotDeadlockClose is the regression for
// the push-mode self-wait: replySender used to call retire()/Close() on a
// handler error, then park forever in stopTransportReceiver's <-done. Close
// from another goroutine (pool Remove, janitor, reload Reset) would then
// block on the same closeOnce.
func TestPacketReceiverHandlerErrorDoesNotDeadlockClose(t *testing.T) {
	conn := &receiverConn{}
	handlerErr := fmt.Errorf("reply send failed")
	handled := make(chan struct{})
	ue := newReceiverTestEndpoint(t, conn, func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error {
		close(handled)
		return handlerErr
	})

	require.True(t, conn.deliver(0))
	select {
	case <-handled:
	case <-time.After(2 * time.Second):
		t.Fatal("handler was never invoked")
	}

	closed := make(chan error, 1)
	go func() { closed <- ue.Close() }()
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked; replySender parked in <-done via retire()->Close()")
	}
	require.True(t, ue.dead.Load(), "handler error must mark the endpoint dead")
	require.Equal(t, 1, conn.unregisterCount(), "Close must still unregister the receiver")
}

// TestPacketReceiverHandlerErrorEventuallyClosesConn proves the mark-only
// retire still releases the transport conn. After selfRemoveFromPool nobody
// else references the endpoint (pool scans and Remove(key, ...) can no longer
// find it), so the endpoint itself must schedule the teardown; without it a
// direct-dial endpoint (no TransportLifecycle watcher) would leak the socket.
func TestPacketReceiverHandlerErrorEventuallyClosesConn(t *testing.T) {
	conn := &receiverConn{}
	handled := make(chan struct{}, 1)
	ue := newReceiverTestEndpoint(t, conn, func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error {
		select {
		case <-handled:
		default:
			close(handled)
		}
		return fmt.Errorf("reply send failed")
	})

	require.True(t, conn.deliver(0))
	select {
	case <-handled:
	case <-time.After(2 * time.Second):
		t.Fatal("handler was never invoked")
	}

	require.Eventually(t, func() bool { return conn.closed.Load() },
		2*time.Second, 10*time.Millisecond,
		"conn was never closed after the handler-error retire")
	require.True(t, ue.dead.Load())
	require.Equal(t, 1, conn.unregisterCount(), "scheduled Close must still unregister the receiver")
}

// TestPacketReceiverReadErrorDoesNotDeadlockClose covers the other push-mode
// self-wait: a hard packet.Err used to call retire() from handleReceivedPacket,
// which is the transport callback itself and likewise must not wait on done.
func TestPacketReceiverReadErrorDoesNotDeadlockClose(t *testing.T) {
	conn := &receiverConn{}
	ue := newReceiverTestEndpoint(t, conn, func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error {
		return nil
	})

	released := atomic.Bool{}
	packet := netproxy.NewReceivedPacket(nil, receiverTestFrom(), fmt.Errorf("upstream reset"), func() {
		released.Store(true)
	})
	require.False(t, ue.handleReceivedPacket(packet), "hard receive error must unregister")
	require.True(t, released.Load(), "hard receive error must release the packet")
	require.True(t, ue.dead.Load(), "hard receive error must mark the endpoint dead")

	closed := make(chan error, 1)
	go func() { closed <- ue.Close() }()
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked after handleReceivedPacket retired the endpoint")
	}
}

// TestPacketReceiverRegistersAfterQueueExists proves deliveries that arrive
// synchronously inside RegisterPacketReceiver (hysteria2 drains queued
// datagrams in-call) are enqueued instead of dropped on a nil queue.
func TestPacketReceiverRegistersAfterQueueExists(t *testing.T) {
	conn := &receiverConn{deliverOnRegister: true}
	got := make(chan []byte, 1)
	ue := newReceiverTestEndpoint(t, conn, func(_ *UdpEndpoint, data []byte, _ netip.AddrPort) error {
		got <- append([]byte(nil), data...)
		return nil
	})

	select {
	case data := <-got:
		require.Equal(t, "sync-register", string(data))
	case <-time.After(2 * time.Second):
		t.Fatal("packet delivered during RegisterPacketReceiver was dropped")
	}
	require.NoError(t, ue.Close())
}

// TestPacketReceiverRegisterSyncHardErrorUnregisters covers the hysteria2
// register-time drain: a hard packet.Err is delivered before Register returns
// the stop func, so the in-callback stopPacketReceiver is a no-op. Close and
// the post-assign stopPacketReceiver must still unregister.
func TestPacketReceiverRegisterSyncHardErrorUnregisters(t *testing.T) {
	conn := &receiverConn{deliverErrOnRegister: fmt.Errorf("session reset")}
	ue := newReceiverTestEndpoint(t, conn, func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error {
		return nil
	})
	require.True(t, ue.dead.Load(), "sync-register hard error must mark the endpoint dead")
	require.Eventually(t, func() bool { return conn.closed.Load() },
		2*time.Second, 10*time.Millisecond,
		"scheduled Close must release the conn")
	require.Equal(t, 1, conn.unregisterCount(), "receiverStop must run after Register returns")
}

// TestPacketReceiverClosedQueueUnregistersReceiver is the race where Close
// flips the queue closed while a delivery is already past the dead check:
// enqueue must return false so the transport drops the receiver.
func TestPacketReceiverClosedQueueUnregistersReceiver(t *testing.T) {
	conn := &receiverConn{}
	ue := newReceiverTestEndpoint(t, conn, func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error {
		return nil
	})
	ue.stopTransportReceiver()
	require.Equal(t, 1, conn.unregisterCount())

	released := atomic.Bool{}
	packet := netproxy.NewReceivedPacket([]byte("late"), receiverTestFrom(), nil, func() {
		released.Store(true)
	})
	require.False(t, ue.handleReceivedPacket(packet), "closed queue must unregister")
	require.True(t, released.Load(), "rejected enqueue must release the packet")
}

// TestPacketReceiverWithRealDirectDialer wires a real fork direct dialer
// (Linux epoll-backed packet receiver registry) into an endpoint and proves
// the full push-mode chain: registration engages, an upstream reply is
// delivered through the shared registry into the reply sender, and Close
// tears everything down.
func TestPacketReceiverWithRealDirectDialer(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = server.Close() }()
	serverAddr := server.LocalAddr().String()

	// UDP has no connection semantics: closing the client endpoint is
	// invisible to this server, so the deferred server.Close() is what ends
	// the read loop.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, peer, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := server.WriteTo(append([]byte("echo:"), buf[:n]...), peer); err != nil {
				return
			}
		}
	}()

	d := direct.NewDirectDialerLaddr(netip.Addr{}, direct.Option{})
	conn, err := d.DialContext(context.Background(), "udp", serverAddr)
	require.NoError(t, err)
	packetConn, ok := conn.(netproxy.PacketConn)
	require.True(t, ok, "direct dialer conn must satisfy netproxy.PacketConn")

	got := make(chan string, 4)
	log := logrus.New()
	log.SetOutput(io.Discard)
	ue := &UdpEndpoint{
		conn: packetConn,
		handler: func(_ *UdpEndpoint, data []byte, _ netip.AddrPort) error {
			select {
			case got <- string(data):
			default:
			}
			return nil
		},
		log:     log,
		poolKey: UdpEndpointKey{Dst: netip.MustParseAddrPort(serverAddr)},
	}
	require.True(t, ue.startTransportReceiver(),
		"real direct dialer conn must register a transport receiver")

	_, err = packetConn.Write([]byte("push-mode-e2e"))
	require.NoError(t, err)

	select {
	case data := <-got:
		require.Equal(t, "echo:push-mode-e2e", data)
	case <-time.After(5 * time.Second):
		t.Fatal("push-mode delivery through the real epoll registry timed out")
	}

	// Close unregisters the receiver, drains the queue, and closes the conn.
	require.NoError(t, ue.Close())
}
