/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

type Ip46 struct {
	Ip4 netip.Addr
	Ip6 netip.Addr
}

func ResolveIp46(ctx context.Context, dialer netproxy.Dialer, dns netip.AddrPort, host string, network string, race bool) (ipv46 *Ip46, err4, err6 error) {
	defer func() {
		log.WithField("err4", err4).
			WithField("err6", err6).
			Tracef("ResolveIp46 %v using %v: A(%v) AAAA(%v)", host, dns, ipv46.Ip4, ipv46.Ip6)
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	var addrs4, addrs6 []netip.Addr
	ctx4, cancel4 := context.WithCancel(ctx)
	ctx6, cancel6 := context.WithCancel(ctx)
	var _err4, _err6 error
	go func() {
		defer func() {
			wg.Done()
			cancel4()
			if race {
				cancel6()
			}
		}()
		var e error
		addrs4, e = ResolveNetip(ctx4, dialer, dns, host, dnsmessage.TypeA, network)
		if e != nil && !errors.Is(e, context.Canceled) {
			_err4 = e
			return
		}
	}()
	go func() {
		defer func() {
			wg.Done()
			cancel6()
			if race {
				cancel4()
			}
		}()
		var e error
		addrs6, e = ResolveNetip(ctx6, dialer, dns, host, dnsmessage.TypeAAAA, network)
		if e != nil && !errors.Is(e, context.Canceled) {
			err6 = e
			return
		}
	}()
	wg.Wait()
	ipv46 = &Ip46{}
	if len(addrs4) != 0 {
		ipv46.Ip4 = addrs4[0]
	}
	if len(addrs6) != 0 {
		ipv46.Ip6 = addrs6[0]
	}
	return ipv46, _err4, _err6
}
