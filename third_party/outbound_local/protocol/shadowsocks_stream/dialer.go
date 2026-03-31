package shadowsocks_stream

import (
	"context"
	"fmt"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

func init() {
	protocol.Register("shadowsocks_stream", NewDialer)
}

const (
	TransportMagicAddr = "<TRANSPORT>"
)

type Dialer struct {
	nextDialer netproxy.Dialer
	addr       string

	EncryptMethod   string
	EncryptPassword string
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	return &Dialer{
		nextDialer:      nextDialer,
		addr:            header.ProxyAddress,
		EncryptMethod:   header.Cipher,
		EncryptPassword: header.Password,
	}, nil
}

// Addr returns forwarder's address
func (d *Dialer) Addr() string {
	return d.addr
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		target, err := socks.ParseAddr(addr)
		if err != nil {
			return nil, err
		}

		conn, err := d.DialTcpTransport(ctx, network)
		if err != nil {
			return nil, err
		}

		if _, err := conn.Write(target); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, err
	case "udp":
		var target socks.Addr
		if addr != TransportMagicAddr {
			target, err = socks.ParseAddr(addr)
			if err != nil {
				return nil, err
			}
		}

		ciph, err := ciphers.NewStreamCipher(d.EncryptMethod, d.EncryptPassword)
		if err != nil {
			return nil, err
		}

		c, err := d.nextDialer.DialContext(ctx, network, d.addr)
		if err != nil {
			return nil, fmt.Errorf("dial to %v error: %w", d.addr, err)
		}
		return NewUdpConn(c.(netproxy.PacketConn), ciph, target, d.addr), nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) DialTcpTransport(ctx context.Context, magicNetwork string) (netproxy.Conn, error) {
	ciph, err := ciphers.NewStreamCipher(d.EncryptMethod, d.EncryptPassword)
	if err != nil {
		return nil, err
	}

	c, err := d.nextDialer.DialContext(ctx, magicNetwork, d.addr)
	if err != nil {
		return nil, fmt.Errorf("dial to %v error: %w", d.addr, err)
	}

	conn := NewTcpConn(c, ciph)

	return conn, err
}

func (d *Dialer) DialUdpTransport(ctx context.Context, magicNetwork string) (netproxy.PacketConn, error) {
	conn, err := d.DialContext(ctx, magicNetwork, TransportMagicAddr)
	if err != nil {
		return nil, err
	}
	return &UdpTransportConn{UdpConn: conn.(*UdpConn)}, nil
}
