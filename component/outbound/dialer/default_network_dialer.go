/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"net"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/netproxy"
)

// defaultNetworkDialer ensures internal outbound proxy dials inherit dae's
// default SO_MARK and MPTCP settings unless the caller already provided them.
type defaultNetworkDialer struct {
	netproxy.Dialer
	mark  uint32
	mptcp bool
}

type lookupIPDialer interface {
	LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error)
}

func newDefaultNetworkDialer(dialer netproxy.Dialer, mark uint32, mptcp bool) netproxy.Dialer {
	if mark == 0 && !mptcp {
		return dialer
	}
	return &defaultNetworkDialer{
		Dialer: dialer,
		mark:   mark,
		mptcp:  mptcp,
	}
}

func (d *defaultNetworkDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	return d.Dialer.DialContext(ctx, d.mergeNetwork(network), addr)
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
