package shadowsocks_2022

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/outbound/protocol/socks5"
)

const maxPSKListLength = 8

// FakeNetPacketConn wraps a PacketConn to override the target address.
// It embeds netproxy.PacketConn directly, so it implements the interface correctly.
// The Addr field is used by UdpConn.WriteTo to determine the actual target.
type FakeNetPacketConn struct {
	netproxy.PacketConn
	Addr string
}

func (c *FakeNetPacketConn) Write(p []byte) (int, error) {
	return c.PacketConn.WriteTo(p, c.Addr)
}

func (c *FakeNetPacketConn) Read(p []byte) (int, error) {
	n, _, err := c.PacketConn.ReadFrom(p)
	return n, err
}

func init() {
	protocol.Register("shadowsocks_2022", NewDialer)
}

type Dialer struct {
	parentDialer netproxy.Dialer
	proxyAddress string
	core         *SS2022Core
	sg           shadowsocks.SaltGenerator
}

func NewDialer(parentDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	conf := ciphers.Aead2022CiphersConf[header.Cipher]
	if conf == nil {
		return nil, fmt.Errorf("unsupported shadowsocks 2022 cipher: %s", header.Cipher)
	}
	if conf.NewCipher == nil {
		return nil, fmt.Errorf("invalid shadowsocks 2022 cipher config: %s", header.Cipher)
	}
	keyStrList := strings.Split(header.Password, ":")
	if len(keyStrList) > maxPSKListLength {
		return nil, fmt.Errorf("too many PSKs: got %d, max %d", len(keyStrList), maxPSKListLength)
	}
	pskList := make([][]byte, len(keyStrList))
	for i, keyStr := range keyStrList {
		key, err := ciphers.ValidateBase64PSK(keyStr, conf.KeyLen)
		if err != nil {
			return nil, err
		}
		pskList[i] = key
	}
	uPSK := pskList[len(pskList)-1]
	core, err := NewSS2022Core(conf, pskList, uPSK)
	if err != nil {
		return nil, err
	}
	sg, err := shadowsocks.NewRandomSaltGenerator(conf.SaltLen)
	if err != nil {
		return nil, err
	}
	return &Dialer{
		parentDialer: parentDialer,
		proxyAddress: header.ProxyAddress,
		core:         core,
		sg:           sg,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	// Extract base protocol from network string (handles "udp", "udp4", "udp6", "udp4(DNS)", etc.)
	proto := magicNetwork.Network
	if len(proto) >= 3 && (proto[0:3] == "tcp" || proto[0:3] == "udp") {
		proto = proto[0:3]
	}
	switch proto {
	case "tcp":
		addrInfo, err := socks5.AddressFromString(addr)
		if err != nil {
			return nil, err
		}
		// Shadowsocks transfer TCP traffic via TCP tunnel.
		conn, err := d.parentDialer.DialContext(ctx, network, d.proxyAddress)
		if err != nil {
			return nil, err
		}
		return NewTCPConnWithContext(ctx, conn.(net.Conn), d.core, d.sg, addrInfo, nil), nil
	case "udp":
		conn, err := d.ListenPacket(ctx, network, d.proxyAddress)
		if err != nil {
			return nil, err
		}
		return &FakeNetPacketConn{
			PacketConn: conn,
			Addr:       addr,
		}, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, network string, addr string) (netproxy.PacketConn, error) {
	// Parse magic network to preserve Mark and Mptcp settings
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	// Shadowsocks transfer UDP traffic via UDP tunnel.
	magicNetwork.Network = "udp"
	network = magicNetwork.Encode()
	conn, err := d.parentDialer.DialContext(ctx, network, d.proxyAddress)
	if err != nil {
		return nil, err
	}
	return NewUdpConnWithContext(ctx, conn.(net.Conn), d.core, nil)
}
