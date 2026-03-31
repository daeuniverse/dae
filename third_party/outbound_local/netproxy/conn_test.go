package netproxy

import (
	"net"
	"testing"
	"time"
)

type fakeConnForUnderlying struct {
	net.Conn
}

func (c *fakeConnForUnderlying) Read(_ []byte) (int, error)         { return 0, nil }
func (c *fakeConnForUnderlying) Write(p []byte) (int, error)        { return len(p), nil }
func (c *fakeConnForUnderlying) Close() error                       { return nil }
func (c *fakeConnForUnderlying) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *fakeConnForUnderlying) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *fakeConnForUnderlying) SetDeadline(_ time.Time) error      { return nil }
func (c *fakeConnForUnderlying) SetReadDeadline(_ time.Time) error  { return nil }
func (c *fakeConnForUnderlying) SetWriteDeadline(_ time.Time) error { return nil }

func TestFakeNetConnUnderlyingConn(t *testing.T) {
	inner := &fakeConnForUnderlying{}
	conn := &FakeNetConn{Conn: inner}
	if got := conn.UnderlyingConn(); got != inner {
		t.Fatalf("unexpected underlying conn: got %T want %T", got, inner)
	}
}
