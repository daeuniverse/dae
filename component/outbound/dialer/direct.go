package dialer

import (
	"golang.org/x/net/proxy"
	"net"
)

var SymmetricDirect = newDirect(false)
var FullconeDirect = newDirect(true)

func NewDirectDialer(option *GlobalOption, fullcone bool) *Dialer {
	if fullcone {
		return newDialer(FullconeDirect, option, true, "direct", "direct", "")
	} else {
		return newDialer(SymmetricDirect, option, true, "direct", "direct", "")
	}
}

type direct struct {
	proxy.Dialer
	netDialer *net.Dialer
	fullCone  bool
}

func newDirect(fullCone bool) proxy.Dialer {
	return &direct{
		netDialer: &net.Dialer{},
		fullCone:  fullCone,
	}
}

func (d *direct) Dial(network, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp":
		return d.netDialer.Dial(network, addr)
	case "udp":
		if d.fullCone {
			conn, err := net.ListenUDP(network, nil)
			if err != nil {
				return nil, err
			}
			return &directUDPConn{UDPConn: conn, FullCone: true}, nil
		} else {
			conn, err := d.netDialer.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			return &directUDPConn{UDPConn: conn.(*net.UDPConn), FullCone: false}, nil
		}
	default:
		return nil, net.UnknownNetworkError(network)
	}
}

type directUDPConn struct {
	*net.UDPConn
	FullCone bool
}

func (c *directUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if !c.FullCone {
		// FIXME: check the addr
		return c.Write(b)
	}
	return c.UDPConn.WriteTo(b, addr)
}

func (c *directUDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if !c.FullCone {
		n, err = c.Write(b)
		return n, 0, err
	}
	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}

func (c *directUDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	if !c.FullCone {
		return c.Write(b)
	}
	return c.UDPConn.WriteToUDP(b, addr)
}
