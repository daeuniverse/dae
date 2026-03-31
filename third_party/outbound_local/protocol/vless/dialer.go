package vless

import (
	"context"
	"fmt"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/vless/vision"
	"github.com/daeuniverse/outbound/protocol/vmess"
)

const (
	XRV = "xtls-rprx-vision"
)

func init() {
	protocol.Register("vless", NewDialer)
}

type Dialer struct {
	proxyAddress string
	nextDialer   netproxy.Dialer
	metadata     protocol.Metadata
	flow         string
	xudp         bool
	key          []byte
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}
	//log.Trace("vless.NewDialer: metadata: %v, password: %v", metadata, password)
	id, err := Password2Key(header.Password)
	if err != nil {
		return nil, err
	}
	flow := header.Feature1
	switch flow {
	case XRV:
		if !metadata.IsClient {
			return nil, fmt.Errorf("unsupported server mode xtls flow type: %v", flow)
		}
	case "":
	default:
		return nil, fmt.Errorf("unsupported xtls flow type: %v", flow)
	}
	return &Dialer{
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
		metadata:     metadata,
		flow:         flow.(string),
		// xudp:         header.Flags&protocol.Flags_VMess_UsePacketAddr == 0,
		xudp: true && flow == XRV,
		key:  id,
	}, nil
}


func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp", "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.IsClient = d.metadata.IsClient

		tcpNetwork := netproxy.MagicNetwork{
			Network: "tcp",
			Mark:    magicNetwork.Mark,
			Mptcp:   magicNetwork.Mptcp,
		}.Encode()
		conn, err := d.nextDialer.DialContext(ctx, tcpNetwork, d.proxyAddress)
		if err != nil {
			return nil, err
		}
		conn, err = NewConn(conn, Metadata{
			Metadata: vmess.Metadata{Metadata: mdata, Network: magicNetwork.Network},
			Flow:     d.flow,
			Mux:      magicNetwork.Network == "udp" && d.xudp,
		}, d.key)
		if err != nil {
			return nil, err
		}
		if d.flow == XRV {
			if d.xudp {
				return vision.NewPacketConn(conn, d.key, magicNetwork.Network, addr)
			}
			return vision.NewConn(conn, d.key)
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
}
