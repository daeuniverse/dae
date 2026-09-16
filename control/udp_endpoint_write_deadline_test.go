package control

import (
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// deadlineBehaviorPacketConn is a netproxy.PacketConn double with explicit
// write-deadline contract knobs: transportDone simulates a TransportLifecycle
// conn (TUIC/Hysteria2/SOCKS5 relay style) and closesSession declares the
// optional destructive netproxy.WriteDeadlineBehavior.
type deadlineBehaviorPacketConn struct {
	setWriteDeadlineCalls int
	transportDone         <-chan struct{}
	closesSession         bool
}

func (c *deadlineBehaviorPacketConn) Read(b []byte) (int, error)  { return 0, io.EOF }
func (c *deadlineBehaviorPacketConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *deadlineBehaviorPacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}

func (c *deadlineBehaviorPacketConn) WriteTo(p []byte, addr string) (int, error) {
	return len(p), nil
}
func (c *deadlineBehaviorPacketConn) Close() error                      { return nil }
func (c *deadlineBehaviorPacketConn) SetDeadline(t time.Time) error     { return nil }
func (c *deadlineBehaviorPacketConn) SetReadDeadline(t time.Time) error { return nil }
func (c *deadlineBehaviorPacketConn) SetWriteDeadline(t time.Time) error {
	c.setWriteDeadlineCalls++
	return nil
}
func (c *deadlineBehaviorPacketConn) TransportDone() <-chan struct{}   { return c.transportDone }
func (c *deadlineBehaviorPacketConn) WriteDeadlineClosesSession() bool { return c.closesSession }

// The decoupling regression: a transport that publishes a TransportDone
// signal but keeps standard (write-abort) write deadlines — e.g. the SOCKS5
// UDP relay, juicity, or the AnyTLS packet stream — must still get the
// stall-probe write deadline armed. TransportLifecycle alone is not
// destructive.
func TestArmWriteDeadlineStillArmsLifecycleConnWithNormalDeadline(t *testing.T) {
	conn := &deadlineBehaviorPacketConn{transportDone: make(chan struct{})}
	ue := newTestEndpoint(conn)

	ue.armWriteDeadline(time.Now())

	if conn.setWriteDeadlineCalls == 0 {
		t.Fatal("armWriteDeadline must arm a lifecycle conn whose write deadline is non-destructive")
	}
	if ue.writeDeadlineArmedAtNano.Load() == 0 {
		t.Fatal("writeDeadlineArmedAtNano should be armed for a lifecycle conn with a normal deadline")
	}
}

// A conn declaring the destructive contract (TUIC/Hysteria2-style session
// timer) must be skipped even without a lifecycle signal.
func TestArmWriteDeadlineSkipsDestructiveWriteDeadlineConn(t *testing.T) {
	conn := &deadlineBehaviorPacketConn{closesSession: true}
	if !netproxy.WriteDeadlineClosesSession(conn) {
		t.Fatal("netproxy helper must see the destructive declaration")
	}
	ue := newTestEndpoint(conn)

	ue.armWriteDeadline(time.Now())

	if conn.setWriteDeadlineCalls != 0 {
		t.Fatal("armWriteDeadline must not call SetWriteDeadline on a conn whose deadline closes the session")
	}
	if ue.writeDeadlineArmedAtNano.Load() != 0 {
		t.Fatal("writeDeadlineArmedAtNano must not be armed for a destructive-write-deadline conn")
	}
}

// End-to-end through the public write path: the destructive marker
// short-circuits arming exactly as the pre-write stall probe would.
func TestUdpEndpointWriteToSkipsArmingDestructiveDeadline(t *testing.T) {
	conn := &deadlineBehaviorPacketConn{closesSession: true}
	ue := newTestEndpoint(conn)

	if _, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53"); err != nil {
		t.Fatalf("WriteTo error = %v", err)
	}
	if conn.setWriteDeadlineCalls != 0 {
		t.Fatal("WriteTo must not arm a session-closing write deadline")
	}
	if ue.writeDeadlineArmedAtNano.Load() != 0 {
		t.Fatal("WriteTo must not record an armed write deadline for a destructive conn")
	}
}
