package control

import (
	stderrors "errors"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	daeerrors "github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/olicesx/quic-go"
)

// mockPacketConn is a minimal netproxy.PacketConn whose WriteTo result is
// scriptable per test.
type mockPacketConn struct {
	writeToFn func(p []byte, addr string) (int, error)
}

func (m *mockPacketConn) Read(b []byte) (int, error)  { return 0, io.EOF }
func (m *mockPacketConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockPacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (m *mockPacketConn) WriteTo(p []byte, addr string) (int, error) {
	if m.writeToFn != nil {
		return m.writeToFn(p, addr)
	}
	return len(p), nil
}
func (m *mockPacketConn) Close() error                       { return nil }
func (m *mockPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func newTestEndpoint(conn netproxy.PacketConn) *UdpEndpoint {
	return &UdpEndpoint{conn: conn}
}

// The ss/vmess regression: protocol dialers that return the encapsulated
// datagram size (len(payload)+overhead) must NOT be treated as a short write.
func TestUdpEndpointWriteToAcceptsOverheadReturn(t *testing.T) {
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			// shadowsocks AEAD returns len(payload)+39 (salt+metadata+tag)
			return len(p) + 39, nil
		},
	}
	ue := newTestEndpoint(mock)
	n, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if err != nil {
		t.Fatalf("WriteTo with overhead return should succeed, got err: %v", err)
	}
	if n != len("hello world")+39 {
		t.Fatalf("expected encapsulated length %d, got %d", len("hello world")+39, n)
	}
	if ue.dead.Load() {
		t.Fatal("endpoint must not be retired when WriteTo returns n > len(b)")
	}
	if !ue.hasSent.Load() {
		t.Fatal("hasSent should be set after a successful write")
	}
}

// A genuine short write (n < len(b)) must still retire the endpoint.
func TestUdpEndpointWriteToRetiresOnRealShortWrite(t *testing.T) {
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			return len(p) - 1, nil
		},
	}
	ue := newTestEndpoint(mock)
	_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if err == nil || !stderrors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected io.ErrShortWrite, got: %v", err)
	}
	if !ue.dead.Load() {
		t.Fatal("endpoint must be retired on a real short write")
	}
}

// Transient write errors never retire the endpoint: the datagram is dropped
// and the session is kept. Session death is owned by the transport signals
// (TransportDone / read-loop EOF), the armed write deadline, and the
// bidirectional-silence rebuild check — not by write-error counting.
func TestUdpEndpointWriteToToleratesTransientErrors(t *testing.T) {
	sentinel := stderrors.New("boom")
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			return 0, sentinel
		},
	}
	ue := newTestEndpoint(mock)
	for i := 1; i <= 10; i++ {
		_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
		if !stderrors.Is(err, sentinel) {
			t.Fatalf("attempt %d: expected sentinel error, got: %v", i, err)
		}
		if !isUdpEndpointWriteTolerated(err) {
			t.Fatalf("attempt %d: expected tolerated error, got: %v", i, err)
		}
		if ue.dead.Load() {
			t.Fatalf("attempt %d: endpoint must survive tolerated errors", i)
		}
	}
}

// A datagram send-queue timeout is congestion, not a dead peer: it is
// tolerated unconditionally so a stall does not tear down a healthy hy2/tuic
// session. Retiring on queue-full would be pointless churn anyway — the
// datagram queue is per-connection, so a redial shares the same full queue.
// Connection death is owned by TransportDone, and a reaped remote session by
// the bidirectional-silence rebuild check.
func TestUdpEndpointWriteToToleratesDatagramQueueTimeout(t *testing.T) {
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			return 0, quic.ErrDatagramQueueFullTimeout
		},
	}
	ue := newTestEndpoint(mock)
	for i := 1; i <= 10; i++ {
		_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
		if !stderrors.Is(err, quic.ErrDatagramQueueFullTimeout) {
			t.Fatalf("attempt %d: expected datagram queue timeout error, got: %v", i, err)
		}
		if !isUdpEndpointWriteTolerated(err) {
			t.Fatalf("attempt %d: expected tolerated error, got: %v", i, err)
		}
		if ue.dead.Load() {
			t.Fatalf("attempt %d: endpoint must survive a datagram send-queue timeout", i)
		}
	}
}

// Hitting the armed write deadline means the transport stopped draining: the
// first deadline-exceeded error retires the endpoint (fail fast). Only
// non-QUIC transports arm the deadline, so this is their stall probe.
func TestUdpEndpointWriteToRetiresOnWriteDeadlineExceeded(t *testing.T) {
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			return 0, os.ErrDeadlineExceeded
		},
	}
	ue := newTestEndpoint(mock)
	_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if !stderrors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline error, got: %v", err)
	}
	if isUdpEndpointWriteTolerated(err) {
		t.Fatal("deadline-exceeded must not be wrapped as tolerated")
	}
	if !ue.dead.Load() {
		t.Fatal("endpoint must retire on the first write-deadline hit")
	}
}

// A closed conn is retired on the first write error, not tolerated.
func TestUdpEndpointWriteToRetiresOnClosedConn(t *testing.T) {
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			return 0, net.ErrClosed
		},
	}
	ue := newTestEndpoint(mock)
	_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if !stderrors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed, got: %v", err)
	}
	if isUdpEndpointWriteTolerated(err) {
		t.Fatal("net.ErrClosed must not be wrapped as tolerated")
	}
	if !ue.dead.Load() {
		t.Fatal("endpoint must retire on a closed conn")
	}
}

// A session that was established (hasReply) but whose client has been silent
// for udpEndpointSendStaleTimeout must be rebuilt on the next write: the pause
// means a new round is starting and the remote (e.g. a game server) may have
// reaped the old session. Retiring now lets the next GetOrCreate dial a fresh
// hy2 session with a new forwarding source port.
func TestUdpEndpointWriteToRebuildsStaleSession(t *testing.T) {
	mock := &mockPacketConn{}
	ue := newTestEndpoint(mock)
	ue.hasReply.Store(true)
	ue.lastSendNano.Store(time.Now().Add(-2 * udpEndpointSendStaleTimeout).UnixNano())
	ue.lastReplyNano.Store(time.Now().Add(-2 * udpEndpointSendStaleTimeout).UnixNano())

	_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if !stderrors.Is(err, daeerrors.ErrClosedConnection) {
		t.Fatalf("expected ErrClosedConnection on stale session, got: %v", err)
	}
	if !ue.dead.Load() {
		t.Fatal("endpoint must be retired when the client session is stale")
	}
}

// An established session whose client sent recently must NOT be rebuilt: this
// keeps normal gameplay (sub-second heartbeats) on the same hy2 session. After
// a successful write the lastSendNano is refreshed.
func TestUdpEndpointWriteToKeepsFreshSession(t *testing.T) {
	mock := &mockPacketConn{}
	ue := newTestEndpoint(mock)
	ue.hasReply.Store(true)
	ue.lastSendNano.Store(time.Now().UnixNano())
	ue.lastReplyNano.Store(time.Now().UnixNano())

	n, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if err != nil {
		t.Fatalf("expected success on fresh session, got: %v", err)
	}
	if n != len("hello world") {
		t.Fatalf("expected %d bytes written, got %d", len("hello world"), n)
	}
	if ue.dead.Load() {
		t.Fatal("fresh session must not be retired")
	}
	if ue.lastSendNano.Load() < time.Now().Add(-time.Second).UnixNano() {
		t.Fatal("lastSendNano must be refreshed after a successful write")
	}
}

// A client that paused briefly but whose server is still replying must NOT be
// rebuilt: the session is mid-round and only the client side is silent. This
// is what keeps a live game from being kicked when the player hits a loading
// or idle stretch.
func TestUdpEndpointWriteToKeepsSessionWhileServerReplyFresh(t *testing.T) {
	mock := &mockPacketConn{}
	ue := newTestEndpoint(mock)
	ue.hasReply.Store(true)
	ue.lastSendNano.Store(time.Now().Add(-2 * udpEndpointSendStaleTimeout).UnixNano())
	ue.lastReplyNano.Store(time.Now().UnixNano())

	n, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if err != nil {
		t.Fatalf("expected success while upstream still replies, got: %v", err)
	}
	if n != len("hello world") {
		t.Fatalf("expected %d bytes written, got %d", len("hello world"), n)
	}
	if ue.dead.Load() {
		t.Fatal("endpoint must not be retired while the upstream is still replying")
	}
}

// Game UDP over a QUIC-backed transport (hy2/tuic, empty SniffedDomain)
// still rebuilds after 5s of bidirectional silence: that is the inter-round
// signal, independent of the transport.
func TestUdpEndpointWriteToRebuildsGameSessionOnQuicTransport(t *testing.T) {
	done := make(chan struct{})
	mock := &deadlineRecordingPacketConn{transportDone: done}
	ue := newTestEndpoint(mock)
	ue.hasReply.Store(true)
	ue.lastSendNano.Store(time.Now().Add(-2 * udpEndpointSendStaleTimeout).UnixNano())
	ue.lastReplyNano.Store(time.Now().Add(-2 * udpEndpointSendStaleTimeout).UnixNano())

	_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if !stderrors.Is(err, daeerrors.ErrClosedConnection) {
		t.Fatalf("expected ErrClosedConnection on stale game session, got: %v", err)
	}
	if !ue.dead.Load() {
		t.Fatal("game UDP over hy2/tuic must still rebuild after 5s of silence")
	}
}

// A sniffed long-lived session (H3/DASH/HLS video) silent for the game 5s
// window must NOT be rebuilt: segment gaps of 6-15s are normal and would
// otherwise look like a new round.
func TestUdpEndpointWriteToKeepsSniffedSessionAcrossGameStaleWindow(t *testing.T) {
	mock := &mockPacketConn{}
	ue := newTestEndpoint(mock)
	ue.SniffedDomain = "video.example.com"
	ue.hasReply.Store(true)
	ue.lastSendNano.Store(time.Now().Add(-2 * udpEndpointSendStaleTimeout).UnixNano())
	ue.lastReplyNano.Store(time.Now().Add(-2 * udpEndpointSendStaleTimeout).UnixNano())

	n, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if err != nil {
		t.Fatalf("expected success across the 5s game window on a sniffed session, got: %v", err)
	}
	if n != len("hello world") {
		t.Fatalf("expected %d bytes written, got %d", len("hello world"), n)
	}
	if ue.dead.Load() {
		t.Fatal("sniffed session must not rebuild after 5s of silence")
	}
}

// Past the 30s QUIC/H3 window, a sniffed session is still rebuilt so a
// peer that actually reaped the session gets a fresh forwarding port.
func TestUdpEndpointWriteToRebuildsSniffedSessionAfterQuicStaleWindow(t *testing.T) {
	mock := &mockPacketConn{}
	ue := newTestEndpoint(mock)
	ue.SniffedDomain = "video.example.com"
	ue.hasReply.Store(true)
	ue.lastSendNano.Store(time.Now().Add(-2 * udpEndpointQuicSendStaleTimeout).UnixNano())
	ue.lastReplyNano.Store(time.Now().Add(-2 * udpEndpointQuicSendStaleTimeout).UnixNano())

	_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if !stderrors.Is(err, daeerrors.ErrClosedConnection) {
		t.Fatalf("expected ErrClosedConnection on QUIC-stale sniffed session, got: %v", err)
	}
	if !ue.dead.Load() {
		t.Fatal("sniffed endpoint must be retired after the 30s silence window")
	}
}

// A probing endpoint (never replied) is not subject to stale-session rebuild:
// the reply guard is only meaningful once the session has been established.
func TestUdpEndpointWriteToProbingNotRebuilt(t *testing.T) {
	mock := &mockPacketConn{}
	ue := newTestEndpoint(mock)
	// hasReply stays false; lastSendNano is irrelevant.

	n, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if err != nil {
		t.Fatalf("expected success while probing, got: %v", err)
	}
	if n != len("hello world") {
		t.Fatalf("expected %d bytes written, got %d", len("hello world"), n)
	}
	if ue.dead.Load() {
		t.Fatal("probing endpoint must not be retired")
	}
}

// deadlineRecordingPacketConn records whether SetWriteDeadline was called and
// optionally implements TransportLifecycle (a QUIC-backed transport) and the
// destructive netproxy.WriteDeadlineBehavior.
type deadlineRecordingPacketConn struct {
	writeToFn              func(p []byte, addr string) (int, error)
	setWriteDeadlineCalled bool
	transportDone          <-chan struct{}
	closesSession          bool
}

func (c *deadlineRecordingPacketConn) Read(b []byte) (int, error)  { return 0, io.EOF }
func (c *deadlineRecordingPacketConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *deadlineRecordingPacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}

func (c *deadlineRecordingPacketConn) WriteTo(p []byte, addr string) (int, error) {
	if c.writeToFn != nil {
		return c.writeToFn(p, addr)
	}
	return len(p), nil
}
func (c *deadlineRecordingPacketConn) Close() error                      { return nil }
func (c *deadlineRecordingPacketConn) SetDeadline(t time.Time) error     { return nil }
func (c *deadlineRecordingPacketConn) SetReadDeadline(t time.Time) error { return nil }
func (c *deadlineRecordingPacketConn) SetWriteDeadline(t time.Time) error {
	c.setWriteDeadlineCalled = true
	return nil
}
func (c *deadlineRecordingPacketConn) TransportDone() <-chan struct{} { return c.transportDone }
func (c *deadlineRecordingPacketConn) WriteDeadlineClosesSession() bool {
	return c.closesSession
}

// A transport that declares a session-closing write deadline (the destructive
// netproxy.WriteDeadlineBehavior contract, e.g. the TUIC/Hysteria2 QUIC
// sessions) must NOT arm a write deadline: datagram send-queue backpressure is
// a normal congestion signal, not a dead peer, and connection death is handled
// by the transport lifecycle watcher.
func TestArmWriteDeadlineSkipsDestructiveDeadlineConn(t *testing.T) {
	conn := &deadlineRecordingPacketConn{transportDone: make(chan struct{}), closesSession: true}
	ue := newTestEndpoint(conn)

	ue.armWriteDeadline(time.Now())

	if conn.setWriteDeadlineCalled {
		t.Fatal("armWriteDeadline must not call SetWriteDeadline on a conn whose deadline closes the session")
	}
	if ue.writeDeadlineArmedAtNano.Load() != 0 {
		t.Fatal("writeDeadlineArmedAtNano must not be armed for a destructive-write-deadline conn")
	}
}

// Transports without a transport-lifecycle channel keep the legacy
// write-deadline behaviour for dead-peer detection.
func TestArmWriteDeadlineStillArmsPlainConn(t *testing.T) {
	conn := &deadlineRecordingPacketConn{}
	ue := newTestEndpoint(conn)

	ue.armWriteDeadline(time.Now())

	if !conn.setWriteDeadlineCalled {
		t.Fatal("armWriteDeadline must keep arming plain (non-lifecycle) conns")
	}
	if ue.writeDeadlineArmedAtNano.Load() == 0 {
		t.Fatal("writeDeadlineArmedAtNano should be armed for a plain conn")
	}
}
