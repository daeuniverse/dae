package mux

import (
	"context"
	"fmt"

	"github.com/daeuniverse/outbound/netproxy"
)

// Mux is a base Mux struct
type Mux struct {
	NextDialer     netproxy.Dialer
	Addr           string
	PassthroughUdp bool
}

func (s *Mux) DialContext(ctx context.Context, network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		c, err := s.NextDialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("[Mux]: dial to %s: %w", s.Addr, err)
		}
		return NewConn(&netproxy.FakeNetConn{
			Conn:  c,
			LAddr: nil,
			RAddr: nil,
		}, MuxOption{
			ID:   [2]byte{0, 0},
			Port: 0,
			Host: "127.0.0.1",
			Type: "",
		}), err
	case "udp":
		if s.PassthroughUdp {
			return s.NextDialer.DialContext(ctx, network, addr)
		}
		// TODO:
		return nil, fmt.Errorf("%w: mux+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
