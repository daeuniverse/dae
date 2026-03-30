/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"errors"
	"net/netip"

	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type Ip46 struct {
	Ip4 netip.Addr
	Ip6 netip.Addr
}

func ResolveIp46(ctx context.Context, dialer netproxy.Dialer, dns netip.AddrPort, host string, network string, race bool) (ipv46 *Ip46, err4, err6 error) {
	ipv46 = &Ip46{}

	var log *logrus.Logger
	if _log := ctx.Value("logger"); _log != nil {
		log = _log.(*logrus.Logger)
		defer func() {
			log.WithField("err4", err4).
				WithField("err6", err6).
				Tracef("ResolveIp46 %v using %v: A(%v) AAAA(%v)", host, dns, ipv46.Ip4, ipv46.Ip6)
		}()
	}

	ctx4, cancel4 := context.WithCancel(ctx)
	ctx6, cancel6 := context.WithCancel(ctx)
	defer cancel4()
	defer cancel6()

	type result struct {
		isIPv4 bool
		addrs  []netip.Addr
		err    error
	}
	resCh := make(chan result, 2)

	go func() {
		addrs, e := ResolveNetip(ctx4, dialer, dns, host, dnsmessage.TypeA, network)
		if errors.Is(e, context.Canceled) {
			e = nil
		}
		if race && len(addrs) > 0 {
			cancel6()
		}
		resCh <- result{isIPv4: true, addrs: addrs, err: e}
	}()
	go func() {
		addrs, e := ResolveNetip(ctx6, dialer, dns, host, dnsmessage.TypeAAAA, network)
		if errors.Is(e, context.Canceled) {
			e = nil
		}
		if race && len(addrs) > 0 {
			cancel4()
		}
		resCh <- result{isIPv4: false, addrs: addrs, err: e}
	}()

	for range 2 {
		select {
		case res := <-resCh:
			if res.isIPv4 {
				if len(res.addrs) > 0 {
					ipv46.Ip4 = res.addrs[0]
				}
				err4 = res.err
			} else {
				if len(res.addrs) > 0 {
					ipv46.Ip6 = res.addrs[0]
				}
				err6 = res.err
			}

			if race && (ipv46.Ip4.IsValid() || ipv46.Ip6.IsValid()) {
				return ipv46, err4, err6
			}
		case <-ctx.Done():
			return ipv46, err4, err6
		}
	}

	return ipv46, err4, err6
}
