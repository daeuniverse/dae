/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"net"

	"github.com/daeuniverse/softwind/netproxy"
)

type blockDialer struct {
	DialCallback func()
}

func (d *blockDialer) Dial(network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		return d.DialTcp(addr)
	case "udp":
		return d.DialUdp(addr)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *blockDialer) DialTcp(addr string) (c netproxy.Conn, err error) {
	d.DialCallback()
	return nil, net.ErrClosed
}
func (d *blockDialer) DialUdp(addr string) (c netproxy.PacketConn, err error) {
	d.DialCallback()
	return nil, net.ErrClosed
}

func NewBlockDialer(option *GlobalOption, dialCallback func()) (netproxy.Dialer, *Property) {
	return &blockDialer{DialCallback: dialCallback}, &Property{
		Name:     "block",
		Address:  "",
		Protocol: "",
		Link:     "",
	}
}
