package shadowsocks

import (
	"context"
	"fmt"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

func init() {
	protocol.Register("shadowsocks", NewDialer)
}

type Dialer struct {
	proxyAddress string
	nextDialer   netproxy.Dialer
	metadata     protocol.Metadata
	key          []byte
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	//log.Trace("shadowsocks.NewDialer: metadata: %v, password: %v", metadata, password)
	return &Dialer{
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
		metadata: protocol.Metadata{
			Cipher:   header.Cipher,
			IsClient: header.IsClient,
		},
		key: common.EVPBytesToKey(header.Password, ciphers.AeadCiphersConf[header.Cipher].KeyLen),
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.Cipher = d.metadata.Cipher
		mdata.IsClient = d.metadata.IsClient

		// Shadowsocks transfer TCP traffic via TCP tunnel.
		conn, err := d.nextDialer.DialContext(ctx, network, d.proxyAddress)
		if err != nil {
			return nil, err
		}
		return NewTCPConn(conn, mdata, d.key, nil)
	case "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.Cipher = d.metadata.Cipher
		mdata.IsClient = d.metadata.IsClient

		// Shadowsocks transfer UDP traffic via UDP tunnel.
		magicNetwork.Network = "udp"
		conn, err := d.nextDialer.DialContext(ctx, magicNetwork.Encode(), d.proxyAddress)
		if err != nil {
			return nil, err
		}
		return NewUdpConn(conn.(netproxy.PacketConn), d.proxyAddress, mdata, d.key, nil)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
