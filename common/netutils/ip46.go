/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 <mzz@tuta.io>
 */

package netutils

import (
	"context"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/proxy"
	"net/netip"
)

type Ip46 struct {
	Ip4 netip.Addr
	Ip6 netip.Addr
}

func ParseIp46(ctx context.Context, dialer proxy.Dialer, dns netip.AddrPort, host string, must46 bool, tcp bool) (ipv46 *Ip46, err error) {
	addrs4, err := ResolveNetip(ctx, dialer, dns, host, dnsmessage.TypeA, tcp)
	if err != nil {
		return nil, err
	}
	if len(addrs4) == 0 && must46 {
		if must46 {
			return nil, fmt.Errorf("domain \"%v\" has no ipv4 record", host)
		} else {
			addrs4 = []netip.Addr{{}}
		}
	}
	addrs6, err := ResolveNetip(ctx, dialer, dns, host, dnsmessage.TypeAAAA, tcp)
	if err != nil {
		return nil, err
	}
	if len(addrs6) == 0 {
		if must46 {
			return nil, fmt.Errorf("domain \"%v\" has no ipv6 record", host)
		} else {
			addrs6 = []netip.Addr{{}}
		}
	}
	return &Ip46{
		Ip4: addrs4[0],
		Ip6: addrs6[0],
	}, nil
}
