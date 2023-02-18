/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package netutils

import (
	"context"
	"github.com/mzz2017/softwind/netproxy"
	"golang.org/x/net/dns/dnsmessage"
	"net/netip"
)

type Ip46 struct {
	Ip4 netip.Addr
	Ip6 netip.Addr
}

func ParseIp46(ctx context.Context, dialer netproxy.Dialer, dns netip.AddrPort, host string, tcp bool) (ipv46 *Ip46, err error) {
	addrs4, err := ResolveNetip(ctx, dialer, dns, host, dnsmessage.TypeA, tcp)
	if err != nil {
		return nil, err
	}
	if len(addrs4) == 0 {
		addrs4 = []netip.Addr{{}}
	}
	addrs6, err := ResolveNetip(ctx, dialer, dns, host, dnsmessage.TypeAAAA, tcp)
	if err != nil {
		return nil, err
	}
	if len(addrs6) == 0 {
		addrs6 = []netip.Addr{{}}
	}
	return &Ip46{
		Ip4: addrs4[0],
		Ip6: addrs6[0],
	}, nil
}
