package vless

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

func (c *Conn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	// FIXME: a compromise on Symmetric NAT
	addr = c.cachedProxyAddrIpIP

	bLen := pool.Get(2)
	defer pool.Put(bLen)
	if _, err = io.ReadFull(&netproxy.ReadWrapper{ReadFunc: c.read}, bLen); err != nil {
		return 0, netip.AddrPort{}, err
	}
	length := int(binary.BigEndian.Uint16(bLen))
	if len(p) < length {
		return 0, netip.AddrPort{}, fmt.Errorf("buf size is not enough")
	}
	n, err = io.ReadFull(&netproxy.ReadWrapper{ReadFunc: c.read}, p[:length])
	return n, addr, err
}

func (c *Conn) WriteTo(p []byte, addr string) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	bLen := pool.Get(2)
	defer pool.Put(bLen)
	binary.BigEndian.PutUint16(bLen, uint16(len(p)))
	if _, err = c.write(bLen); err != nil {
		return 0, err
	}
	return c.write(p)
}
