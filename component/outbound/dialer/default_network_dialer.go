/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"net"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/netproxy"
)

const (
	defaultUDPReadBufferSize  = 4 << 20
	defaultUDPWriteBufferSize = 4 << 20
)

// defaultNetworkDialer ensures internal outbound proxy dials inherit dae's
// default SO_MARK and MPTCP settings unless the caller already provided them.
type defaultNetworkDialer struct {
	netproxy.Dialer
	mark               uint32
	mptcp              bool
	udpReadBufferSize  int
	udpWriteBufferSize int
}

type lookupIPDialer interface {
	LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error)
}

type udpReadBufferSetter interface {
	SetReadBuffer(size int) error
}

type udpWriteBufferSetter interface {
	SetWriteBuffer(size int) error
}

func newDefaultNetworkDialer(dialer netproxy.Dialer, mark uint32, mptcp bool) netproxy.Dialer {
	if mark == 0 && !mptcp && defaultUDPReadBufferSize <= 0 && defaultUDPWriteBufferSize <= 0 {
		return dialer
	}
	return &defaultNetworkDialer{
		Dialer:             dialer,
		mark:               mark,
		mptcp:              mptcp,
		udpReadBufferSize:  defaultUDPReadBufferSize,
		udpWriteBufferSize: defaultUDPWriteBufferSize,
	}
}

func (d *defaultNetworkDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, d.mergeNetwork(network), addr)
	if err != nil {
		return nil, err
	}
	d.tuneUDPBuffers(network, conn)
	return conn, nil
}

func (d *defaultNetworkDialer) LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error) {
	resolver, ok := d.Dialer.(lookupIPDialer)
	if !ok {
		return net.DefaultResolver.LookupIPAddr(ctx, host)
	}
	return resolver.LookupIPAddr(ctx, d.mergeNetwork(network), host)
}

func (d *defaultNetworkDialer) mergeNetwork(network string) string {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return common.MagicNetwork(network, d.mark, d.mptcp)
	}
	if magicNetwork.Mark == 0 {
		magicNetwork.Mark = d.mark
	}
	if !magicNetwork.Mptcp {
		magicNetwork.Mptcp = d.mptcp
	}
	return common.MagicNetworkWithIPVersion(magicNetwork.Network, magicNetwork.Mark, magicNetwork.Mptcp, magicNetwork.IPVersion)
}

func (d *defaultNetworkDialer) tuneUDPBuffers(network string, conn netproxy.Conn) {
	if conn == nil || !isUDPNetwork(network) {
		return
	}
	if d.udpReadBufferSize > 0 {
		if c, ok := conn.(udpReadBufferSetter); ok {
			_ = c.SetReadBuffer(d.udpReadBufferSize)
		}
	}
	if d.udpWriteBufferSize > 0 {
		if c, ok := conn.(udpWriteBufferSetter); ok {
			_ = c.SetWriteBuffer(d.udpWriteBufferSize)
		}
	}
}

func isUDPNetwork(network string) bool {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err == nil {
		network = magicNetwork.Network
	}
	switch network {
	case "udp", "udp4", "udp6":
		return true
	default:
		return false
	}
}
