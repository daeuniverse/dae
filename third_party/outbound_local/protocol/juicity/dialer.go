package juicity

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/outbound/protocol/trojanc"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/google/uuid"
	"github.com/olicesx/quic-go"
)

func init() {
	protocol.Register("juicity", NewDialer)
}

type Dialer struct {
	clientRing *clientRing

	proxyAddress string
	proxyUDPAddr *net.UDPAddr
	nextDialer   netproxy.Dialer
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	id, err := uuid.Parse(header.User)
	if err != nil {
		return nil, fmt.Errorf("parse UUID: %w", err)
	}
	// ensure server's incoming stream can handle correctly, increase to 1.1x
	maxOpenIncomingStreams := int64(100)
	reservedStreamsCapability := maxOpenIncomingStreams / 5
	if reservedStreamsCapability < 1 {
		reservedStreamsCapability = 1
	}
	if reservedStreamsCapability > 5 {
		reservedStreamsCapability = 5
	}
	proxyUDPAddr, err := net.ResolveUDPAddr("udp", header.ProxyAddress)
	if err != nil {
		return nil, err
	}
	return &Dialer{
		clientRing: newClientRing(func(capabilityCallback func(n int64)) *clientImpl {
			ctx, cancel := context.WithCancel(context.Background())
			return &clientImpl{
				ClientOption: &ClientOption{
					TlsConfig: header.TlsConfig,
					QuicConfig: &quic.Config{
						InitialStreamReceiveWindow:     common.InitialStreamReceiveWindow,
						MaxStreamReceiveWindow:         common.MaxStreamReceiveWindow,
						InitialConnectionReceiveWindow: common.InitialConnectionReceiveWindow,
						MaxConnectionReceiveWindow:     common.MaxConnectionReceiveWindow,
						KeepAlivePeriod:                5 * time.Second,
						DisablePathMTUDiscovery:        false,
						EnableDatagrams:                false,
						HandshakeIdleTimeout:           8 * time.Second,
						CapabilityCallback:             capabilityCallback,
					},
					Uuid:                 id,
					Password:             header.Password,
					CongestionController: header.Feature1.(string),
					CWND:                 10,
					Ctx:                  ctx,
					Cancel:               cancel,
					UnderlayAuth:         make(chan *UnderlayAuth, 64),
				},
			}
		}, reservedStreamsCapability),
		proxyAddress: header.ProxyAddress,
		proxyUDPAddr: proxyUDPAddr,
		nextDialer:   nextDialer,
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
			rAddr)
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
		mdata.IsClient = true
		udpNetwork := network
		if magicNetwork.Network == "tcp" {
			udpNetwork = netproxy.MagicNetwork{
				Network: "udp",
				Mark:    magicNetwork.Mark,
			}.Encode()
		}
		if magicNetwork.Network == "udp" {
			switch mdata.Port {
			// case 443, 8443, 5201:
			case 0:
				iv, psk, err := d.clientRing.DialAuth(ctx, &trojanc.Metadata{
					Metadata: mdata,
					Network:  magicNetwork.Network,
				}, d.nextDialer, d.dialFuncFactory(udpNetwork, d.proxyUDPAddr))
				if err != nil {
					return nil, err
				}
				key, err := underlayKey(psk)
				if err != nil {
					return nil, err
				}
				innerAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(mdata.Hostname, strconv.Itoa(int(mdata.Port))))
				if err != nil {
					return nil, err
				}
				transport, _, err := d.dialFuncFactory(udpNetwork, d.proxyUDPAddr)(context.TODO(), d.nextDialer)
				if err != nil {
					return nil, err
				}
				return &TransportPacketConn{
					Transport: transport,
					proxyAddr: d.proxyUDPAddr,
					tgt:       innerAddr.AddrPort(),
					key:       key,
					firstIv:   iv,
				}, nil
			}
		}
		conn, err := d.clientRing.DialContext(ctx, &trojanc.Metadata{
			Metadata: mdata,
			Network:  magicNetwork.Network,
		}, d.nextDialer,
			d.dialFuncFactory(udpNetwork, d.proxyUDPAddr),
		)
		if err != nil {
			return nil, err
		}
		if magicNetwork.Network == "tcp" {
			time.AfterFunc(100*time.Millisecond, func() {
				// avoid the situation where the server sends messages first
				if _, err = conn.Write(nil); err != nil {
					return
				}
			})
			return conn, nil
		} else {
			return &PacketConn{
				Conn: conn,
			}, nil
		}

	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
}

func underlayKey(psk []byte) (key *shadowsocks.Key, err error) {
	return &shadowsocks.Key{
		CipherConf: CipherConf,
		MasterKey:  psk,
	}, nil
}

func (d *Dialer) DialCmdMsg(ctx context.Context, cmd protocol.MetadataCmd) (c netproxy.Conn, err error) {
	conn, err := d.clientRing.DialContext(ctx, &trojanc.Metadata{
		Metadata: protocol.Metadata{
			Type:     protocol.MetadataTypeMsg,
			Cmd:      cmd,
			IsClient: true,
		},
	}, d.nextDialer,
		d.dialFuncFactory("udp", d.proxyUDPAddr),
	)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
