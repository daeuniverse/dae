package tuic

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/google/uuid"
	"github.com/olicesx/quic-go"
)

func init() {
	protocol.Register("tuic", NewDialer)
}

type Dialer struct {
	clientRing *clientRing

	proxyAddress string
	proxyUDPAddr *net.UDPAddr
	nextDialer   netproxy.Dialer
	metadata     protocol.Metadata
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}

	id, err := uuid.Parse(header.User)
	if err != nil {
		return nil, fmt.Errorf("parse UUID: %w", err)
	}
	// ensure server's incoming stream can handle correctly, increase to 1.1x
	maxDatagramFrameSize := 1400
	udpRelayMode := common.NATIVE
	if header.Flags&protocol.Flags_Tuic_UdpRelayModeQuic > 0 {
		_ = header // avoid empty branch warning
		// FIXME: QUIC has severe performance problems.
		// udpRelayMode = common.QUIC
	}
	proxyUDPAddr, err := net.ResolveUDPAddr("udp", header.ProxyAddress)
	if err != nil {
		return nil, err
	}
	return &Dialer{
		clientRing: newClientRing(func(capabilityCallback func(n int64)) *clientImpl {
			return &clientImpl{
				ClientOption: &ClientOption{
					TlsConfig: header.TlsConfig,
					QuicConfig: &quic.Config{
						InitialStreamReceiveWindow:     common.InitialStreamReceiveWindow,
						MaxStreamReceiveWindow:         common.MaxStreamReceiveWindow,
						InitialConnectionReceiveWindow: common.InitialConnectionReceiveWindow,
						MaxConnectionReceiveWindow:     common.MaxConnectionReceiveWindow,
						KeepAlivePeriod:                3 * time.Second,
						DisablePathMTUDiscovery:        false,
						EnableDatagrams:                true,
						HandshakeIdleTimeout:           8 * time.Second,
						CapabilityCallback:             capabilityCallback,
					},
					Uuid:                  id,
					Password:              header.Password,
					UdpRelayMode:          udpRelayMode,
					CongestionController:  header.Feature1.(string),
					ReduceRtt:             false,
					CWND:                  10,
					MaxUdpRelayPacketSize: maxDatagramFrameSize,
				},
				udp: true,
			}
		}, 10),
		proxyAddress: header.ProxyAddress,
		proxyUDPAddr: proxyUDPAddr,
		nextDialer:   nextDialer,
		metadata:     metadata,
	}, nil
}

func (d *Dialer) dialFuncFactory(udpNetwork string, rAddr net.Addr) common.DialFunc {
	return func(ctx context.Context, dialer netproxy.Dialer) (transport *quic.Transport, addr net.Addr, err error) {
		conn, err := dialer.DialContext(ctx, udpNetwork, d.proxyAddress)
		if err != nil {
			return nil, nil, err
		}
		pc := netproxy.NewFakeNetPacketConn(
			conn.(netproxy.PacketConn),
			net.UDPAddrFromAddrPort(common.GetUniqueFakeAddrPort()),
			rAddr,
		)
		transport = &quic.Transport{Conn: pc}
		return transport, rAddr, nil
	}
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
		udpNetwork := network
		if magicNetwork.Network == "tcp" {
			udpNetwork = netproxy.MagicNetwork{
				Network: "udp",
				Mark:    magicNetwork.Mark,
			}.Encode()
			tcpConn, err := d.clientRing.DialContextWithDialer(ctx, &mdata, d.nextDialer,
				d.dialFuncFactory(udpNetwork, d.proxyUDPAddr),
			)
			if err != nil {
				return nil, err
			}
			return tcpConn, nil
		} else {
			udpConn, err := d.clientRing.ListenPacketWithDialer(ctx, &mdata, d.nextDialer,
				d.dialFuncFactory(udpNetwork, d.proxyUDPAddr),
			)
			if err != nil {
				return nil, err
			}
			udpConn.(*quicStreamPacketConn).target = addr
			return udpConn, nil
		}

	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
}
