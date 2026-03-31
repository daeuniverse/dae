package netproxy

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/olicesx/quic-go"
)

var UnsupportedTunnelTypeError = net.UnknownNetworkError("unsupported tunnel type")

type FullConn interface {
	Conn
	PacketConn
}

type Conn interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

type PacketConn interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	ReadFrom(p []byte) (n int, addr netip.AddrPort, err error)
	WriteTo(p []byte, addr string) (n int, err error)
	Close() error
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

type FakeNetConn struct {
	Conn
	LAddr net.Addr
	RAddr net.Addr
}

func (conn *FakeNetConn) UnderlyingConn() net.Conn {
	if underlying, ok := conn.Conn.(net.Conn); ok {
		return underlying
	}
	return nil
}

func (conn *FakeNetConn) LocalAddr() net.Addr {
	return conn.LAddr
}
func (conn *FakeNetConn) RemoteAddr() net.Addr {
	return conn.RAddr
}

type fakeNetPacketConn struct {
	PacketConn
	LAddr net.Addr
	RAddr net.Addr
}

type FakeNetPacketConn interface {
	net.PacketConn
	net.Conn
}

func NewFakeNetPacketConn(conn PacketConn, LAddr net.Addr, RAddr net.Addr) FakeNetPacketConn {
	fakeNetConn := &fakeNetPacketConn{
		PacketConn: conn,
		LAddr:      LAddr,
		RAddr:      RAddr,
	}
	if _, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		return &fakeNetPacketConn2{
			fakeNetPacketConn: fakeNetConn,
		}
	}
	return fakeNetConn
}

// ReadMsgUDP implements quic.OOBCapablePacketConn.
func (conn *fakeNetPacketConn) ReadMsgUDP(b []byte, oob []byte) (n int, oobn int, flags int, addr *net.UDPAddr, err error) {
	c, ok := conn.PacketConn.(interface {
		ReadMsgUDP(b []byte, oob []byte) (n int, oobn int, flags int, addr *net.UDPAddr, err error)
	})
	if !ok {
		return 0, 0, 0, nil, fmt.Errorf("connection doesn't allow to get ReadMsgUDP. Not a *net.UDPConn? : %T", conn.PacketConn)
	}
	return c.ReadMsgUDP(b, oob)
}

// WriteMsgUDP implements quic.OOBCapablePacketConn.
func (conn *fakeNetPacketConn) WriteMsgUDP(b []byte, oob []byte, addr *net.UDPAddr) (n int, oobn int, err error) {
	c, ok := conn.PacketConn.(interface {
		WriteMsgUDP(b []byte, oob []byte, addr *net.UDPAddr) (n int, oobn int, err error)
	})
	if !ok {
		return 0, 0, fmt.Errorf("connection doesn't allow to get WriteMsgUDP. Not a *net.UDPConn? : %T", conn.PacketConn)
	}
	return c.WriteMsgUDP(b, oob, addr)
}

func (conn *fakeNetPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, a, err := conn.PacketConn.ReadFrom(p)
	return n, net.UDPAddrFromAddrPort(a), err
}
func (conn *fakeNetPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return conn.PacketConn.WriteTo(p, addr.String())
}
func (conn *fakeNetPacketConn) LocalAddr() net.Addr {
	return conn.LAddr
}
func (conn *fakeNetPacketConn) RemoteAddr() net.Addr {
	return conn.RAddr
}
func (conn *fakeNetPacketConn) SetWriteBuffer(size int) error {
	c, ok := conn.PacketConn.(interface{ SetWriteBuffer(int) error })
	if !ok {
		return fmt.Errorf("connection doesn't allow setting of send buffer size. Not a *net.UDPConn? : %T", conn.PacketConn)
	}
	return c.SetWriteBuffer(size)
}
func (conn *fakeNetPacketConn) SetReadBuffer(size int) error {
	c, ok := conn.PacketConn.(interface{ SetReadBuffer(int) error })
	if !ok {
		return fmt.Errorf("connection doesn't allow setting of send buffer size. Not a *net.UDPConn? : %T", conn.PacketConn)
	}
	return c.SetReadBuffer(size)
}

type fakeNetPacketConn2 struct {
	*fakeNetPacketConn
}

func (conn *fakeNetPacketConn2) SyscallConn() (syscall.RawConn, error) {
	c, ok := conn.PacketConn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return nil, fmt.Errorf("connection doesn't allow to get Syscall.RawConn. Not a *net.UDPConn? : %T", conn.PacketConn)
	}
	return c.SyscallConn()
}

var _ quic.OOBCapablePacketConn = &fakeNetPacketConn2{}
