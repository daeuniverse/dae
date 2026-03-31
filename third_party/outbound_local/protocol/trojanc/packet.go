package trojanc

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

type PacketConn struct {
	*Conn
	domainIpMapping sync.Map
}

func (c *PacketConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, net.JoinHostPort(c.metadata.Hostname, strconv.Itoa(int(c.metadata.Port))))
}

func (c *PacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}

func (c *PacketConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	m := Metadata{}
	if _, err = m.Unpack(c.Conn); err != nil {
		return 0, netip.AddrPort{}, err
	}
	if addr, err = m.DomainIpMapping(&c.domainIpMapping); err != nil {
		return 0, netip.AddrPort{}, err
	}

	buf := pool.Get(2)
	defer buf.Put()
	if _, err = io.ReadFull(c.Conn, buf[:2]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	length := binary.BigEndian.Uint16(buf)
	buf = pool.Get(2 + int(length))
	defer buf.Put()
	if _, err = io.ReadFull(c.Conn, buf); err != nil {
		return 0, netip.AddrPort{}, err
	}
	n = copy(p, buf[2:])
	return n, addr, nil
}

func (c *PacketConn) WriteTo(p []byte, addr string) (n int, err error) {
	_metadata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return 0, err
	}
	metadata := Metadata{
		Metadata: _metadata,
		Network:  "udp",
	}
	buf := pool.Get(metadata.Len() + 4 + len(p))
	defer pool.Put(buf)
	SealUDP(metadata, buf, p)
	_, err = c.Conn.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func SealUDP(metadata Metadata, dst []byte, data []byte) []byte {
	n := metadata.Len()
	// copy first to allow overlap
	copy(dst[n+4:], data)
	metadata.PackTo(dst)
	binary.BigEndian.PutUint16(dst[n:], uint16(len(data)))
	copy(dst[n+2:], CRLF)
	return dst[:n+4+len(data)]
}
