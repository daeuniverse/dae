package anytls

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

var (
	_ netproxy.Conn       = (*stream)(nil)
	_ netproxy.PacketConn = (*packetStream)(nil)
)

type stream struct {
	*session
	pr *io.PipeReader
	pw *io.PipeWriter

	writeMutex sync.Mutex
	readMutex  sync.Mutex

	closed atomic.Bool

	id uint32
}

func newStream(session *session, id uint32) *stream {
	pr, pw := io.Pipe()
	return &stream{
		session: session,
		pr:      pr,
		pw:      pw,
		id:      id,
	}
}

func (c *stream) Write(b []byte) (n int, err error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	frame := newFrame(cmdPSH, c.id)
	frame.data = b
	return writeFrame(c.session, frame)
}

func (c *stream) Read(b []byte) (n int, err error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	return c.pr.Read(b)
}

func (c *stream) remoteClose() error {
	if c.closed.CompareAndSwap(false, true) {
		c.removeStream(c.id)
		if c.pw != nil {
			_ = c.pw.Close()
		}
		_ = c.pr.Close()
		return nil
	}
	return nil
}

func (c *stream) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.removeStream(c.id)
		frame := newFrame(cmdFIN, c.id)
		_, _ = writeFrame(c.session, frame)
		_ = c.pw.Close()
		_ = c.pr.Close()
		return nil
	}
	return nil
}

func (c *stream) LocalAddr() net.Addr {
	return c.session.conn.(net.Conn).LocalAddr()
}

func (c *stream) RemoteAddr() net.Addr {
	return c.session.conn.(net.Conn).RemoteAddr()
}

func (c *stream) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *stream) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *stream) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type packetStream struct {
	*stream

	addr         string
	udpWriteAddr atomic.Bool
}

func (ps *packetStream) Read(p []byte) (n int, err error) {
	n, _, err = ps.ReadFrom(p)
	return n, err
}

func (ps *packetStream) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	if ps.closed.Load() {
		return 0, netip.AddrPort{}, net.ErrClosed
	}
	ps.readMutex.Lock()
	defer ps.readMutex.Unlock()

	var length uint16
	if err := binary.Read(ps.pr, binary.BigEndian, &length); err != nil {
		return 0, netip.AddrPort{}, err
	}
	if len(p) < int(length) {
		return 0, netip.AddrPort{}, io.ErrShortBuffer
	}
	n, err := io.ReadFull(ps.pr, p[:length])
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	addr, _ := netip.ParseAddrPort(ps.addr)
	return n, addr, nil
}

func (ps *packetStream) Write(p []byte) (n int, err error) {
	return ps.WriteTo(p, ps.addr)
}

func (ps *packetStream) WriteTo(p []byte, addr string) (n int, err error) {
	if ps.closed.Load() {
		return 0, net.ErrClosed
	}
	ps.writeMutex.Lock()
	defer ps.writeMutex.Unlock()

	if ps.udpWriteAddr.CompareAndSwap(false, true) {
		tgtAddr, err := socks.ParseAddr(addr)
		if err != nil {
			return 0, err
		}
		data := pool.Get(1 + len(tgtAddr) + 2 + len(p))
		defer pool.Put(data)
		// connected mode
		data[0] = 1
		copy(data[1:], tgtAddr)
		binary.BigEndian.PutUint16(data[1+len(tgtAddr):], uint16(len(p)))
		copy(data[1+len(tgtAddr)+2:], p)

		frame := newFrame(cmdPSH, ps.id)
		frame.data = data
		if _, err := writeFrame(ps.session, frame); err != nil {
			return 0, err
		}
		return len(p), nil
	}

	data := pool.Get(2 + len(p))
	defer pool.Put(data)
	binary.BigEndian.PutUint16(data, uint16(len(p)))
	copy(data[2:], p)

	frame := newFrame(cmdPSH, ps.id)
	frame.data = data
	if _, err := writeFrame(ps.session, frame); err != nil {
		return 0, err
	}
	return len(p), nil
}
