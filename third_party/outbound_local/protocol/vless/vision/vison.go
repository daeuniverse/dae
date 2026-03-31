// Package vision implements VLESS flow `xtls-rprx-vision` introduced by Xray-core.
package vision

import (
	"errors"

	"github.com/daeuniverse/outbound/netproxy"
)

var ErrNotTLS13 = errors.New("XTLS Vision based on TLS 1.3 outer connection")

func NewPacketConn(conn netproxy.Conn, userUUID []byte, network string, addr string) (*PacketConn, error) {
	c, err := NewConn(conn, userUUID)
	return &PacketConn{c, network, addr}, err
}

func NewConn(conn netproxy.Conn, userUUID []byte) (*Conn, error) {
	c := &Conn{
		overlayConn:                conn,
		userUUID:                   userUUID,
		packetsToFilter:            6,
		needHandshake:              true,
		readFilterUUID:             true,
		writeFilterApplicationData: true,
	}
	c.writer = &writeWrapper{
		vision: c,
	}
	c.reader = &readWrapper{
		vision: c,
	}
	underlayConn, tlsConn, connType, connPointer, err := visionIntrinsicConn(conn)
	if err != nil {
		return nil, err
	}
	readBuffers, err := visionTLSReadBuffersFor(connType, connPointer)
	if err != nil {
		return nil, err
	}
	c.Conn = underlayConn
	c.tlsConn = tlsConn
	c.input = readBuffers.input
	c.rawInput = readBuffers.rawInput
	return c, nil
}
