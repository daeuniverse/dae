package udphop

import (
	"net"
	"testing"
	"time"
)

type stubPacketConn struct {
	lastWriteAddr string
}

func (c *stubPacketConn) ReadFrom(_ []byte) (n int, addr net.Addr, err error) {
	return 0, nil, net.ErrClosed
}

func (c *stubPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	c.lastWriteAddr = addr.String()
	return len(b), nil
}

func (c *stubPacketConn) Close() error {
	return nil
}

func (c *stubPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *stubPacketConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *stubPacketConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *stubPacketConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

func TestUDPHopPacketConnWritesToCurrentHopAddr(t *testing.T) {
	currentAddr := &hostPortAddr{
		Host: "example.com",
		Port: 8443,
	}
	stubConn := &stubPacketConn{}
	conn := &udpHopPacketConn{
		Addr:        &UDPHopAddr{Host: "example.com", PortStr: "443,8443"},
		currentAddr: currentAddr,
		currentConn: stubConn,
		closeChan:   make(chan struct{}),
	}

	if _, err := conn.WriteTo([]byte("hello"), nil); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	if got, want := stubConn.lastWriteAddr, "example.com:8443"; got != want {
		t.Fatalf("lastWriteAddr = %q, want %q", got, want)
	}
}

func TestUDPHopPacketConnRemoteAddrReturnsCurrentIPv6HopAddr(t *testing.T) {
	currentAddr := &net.UDPAddr{
		IP:   net.ParseIP("2001:db8::1"),
		Port: 8443,
	}
	conn := &udpHopPacketConn{
		Addr:        &UDPHopAddr{Host: "2001:db8::1", PortStr: "443,8443"},
		currentAddr: currentAddr,
	}

	addr := conn.RemoteAddr()
	if addr == nil {
		t.Fatal("RemoteAddr() returned nil")
	}
	if got, want := addr.String(), currentAddr.String(); got != want {
		t.Fatalf("RemoteAddr() = %q, want %q", got, want)
	}
}

func TestUDPHopPacketConnReadFromReturnsPacketSourceAddr(t *testing.T) {
	packetAddr := &net.UDPAddr{
		IP:   net.ParseIP("2001:db8::2"),
		Port: 8443,
	}
	conn := &udpHopPacketConn{
		Addr:        &UDPHopAddr{Host: "2001:db8::1", PortStr: "443,8443"},
		currentAddr: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443},
		recvQueue:   make(chan *udpPacket, 1),
		closeChan:   make(chan struct{}),
	}
	conn.recvQueue <- &udpPacket{
		Buf:  []byte("hello"),
		N:    len("hello"),
		Addr: packetAddr,
	}

	buf := make([]byte, len("hello"))
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if got, want := string(buf[:n]), "hello"; got != want {
		t.Fatalf("ReadFrom() payload = %q, want %q", got, want)
	}
	if addr == nil {
		t.Fatal("ReadFrom() returned nil addr")
	}
	if got, want := addr.String(), packetAddr.String(); got != want {
		t.Fatalf("ReadFrom() addr = %q, want %q", got, want)
	}
}
