package client

import (
	"net"
	"testing"
	"time"
)

type packetConnWithRemoteAddr struct {
	remote net.Addr
}

func (c *packetConnWithRemoteAddr) ReadFrom(_ []byte) (n int, addr net.Addr, err error) {
	return 0, nil, net.ErrClosed
}

func (c *packetConnWithRemoteAddr) WriteTo(b []byte, _ net.Addr) (n int, err error) {
	return len(b), nil
}

func (c *packetConnWithRemoteAddr) Close() error {
	return nil
}

func (c *packetConnWithRemoteAddr) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *packetConnWithRemoteAddr) SetDeadline(_ time.Time) error {
	return nil
}

func (c *packetConnWithRemoteAddr) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *packetConnWithRemoteAddr) SetWriteDeadline(_ time.Time) error {
	return nil
}

func (c *packetConnWithRemoteAddr) RemoteAddr() net.Addr {
	return c.remote
}

func TestQuicRemoteAddrPrefersPacketConnRemoteAddr(t *testing.T) {
	fallback := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 443}
	remote := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 2), Port: 8443}
	conn := &packetConnWithRemoteAddr{remote: remote}

	if got := quicRemoteAddr(conn, fallback); got.String() != remote.String() {
		t.Fatalf("quicRemoteAddr() = %q, want %q", got.String(), remote.String())
	}
}

func TestQuicRemoteAddrFallsBackWhenPacketConnHasNoRemoteAddr(t *testing.T) {
	fallback := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 443}
	conn := &packetConnWithRemoteAddr{}

	if got := quicRemoteAddr(conn, fallback); got.String() != fallback.String() {
		t.Fatalf("quicRemoteAddr() = %q, want %q", got.String(), fallback.String())
	}
}
