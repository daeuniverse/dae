/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/daeuniverse/dae/component/dns"
)

// DnsRequestSnapshot contains the immutable routing facts needed to resolve a
// DNS request. Transport sockets, packet recorders, and response writers stay
// in the protocol adapters.
type DnsRequestSnapshot struct {
	RealSrc netip.AddrPort
	RealDst netip.AddrPort

	routingResult    bpfRoutingResult
	hasRoutingResult bool
}

func dnsRequestSnapshotFromUDPRequest(req *udpRequest) DnsRequestSnapshot {
	if req == nil {
		return DnsRequestSnapshot{}
	}
	snapshot := DnsRequestSnapshot{
		RealSrc: req.realSrc,
		RealDst: req.realDst,
	}
	if req.routingResult != nil {
		snapshot.routingResult = *req.routingResult
		snapshot.hasRoutingResult = true
	}
	return snapshot
}

func (snapshot DnsRequestSnapshot) routingResultForRoute() *bpfRoutingResult {
	if !snapshot.hasRoutingResult {
		return nil
	}
	routingResult := snapshot.routingResult
	return &routingResult
}

func (runtime *dnsControllerRuntimeState) chooseBestDnsDialer(ctx context.Context, snapshot DnsRequestSnapshot, upstream *dns.Upstream) (*dialArgument, error) {
	if runtime == nil || runtime.bestDialerChooser == nil {
		return nil, fmt.Errorf("dns controller runtime best dialer chooser is not configured")
	}
	return runtime.bestDialerChooser(ctx, snapshot, upstream)
}
