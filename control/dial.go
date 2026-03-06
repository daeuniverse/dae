/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type proxyDialParam struct {
	Outbound    consts.OutboundIndex
	Domain      string
	Mac         [6]uint8
	Dscp        uint8
	ProcessName [16]uint8
	Src         netip.AddrPort
	Dest        netip.AddrPort
	Mark        uint32
	Network     string // e.g. "tcp", "udp"
}

type proxyDialResult struct {
	Outbound             *outbound.DialerGroup
	Dialer               *dialer.Dialer
	DialTarget           string
	Network              string
	Mark                 uint32
	SniffedDomain        string
	IsDialIp             bool
	OrigNetworkType      string
	SelectionNetworkType string
}

func (c *ControlPlane) chooseProxyDialer(ctx context.Context, p *proxyDialParam) (*proxyDialResult, error) {
	outboundIndex := p.Outbound
	domain := p.Domain
	src := p.Src
	dst := p.Dest
	mark := p.Mark

	dialTarget, shouldReroute, dialIp := c.ChooseDialTarget(outboundIndex, dst, domain)
	if shouldReroute {
		outboundIndex = consts.OutboundControlPlaneRouting
	}

	if outboundIndex == consts.OutboundControlPlaneRouting {
		routingResult := &bpfRoutingResult{
			Mark:     mark,
			Mac:      p.Mac,
			Outbound: uint8(p.Outbound),
			Pname:    p.ProcessName,
			Dscp:     p.Dscp,
		}
		var newMark uint32
		var err error
		proto := consts.L4ProtoType_TCP
		if p.Network == "udp" {
			proto = consts.L4ProtoType_UDP
		}
		if outboundIndex, newMark, _, err = c.Route(src, dst, domain, proto, routingResult); err != nil {
			return nil, err
		}
		mark = newMark
		// Reset dialTarget.
		dialTarget, _, dialIp = c.ChooseDialTarget(outboundIndex, dst, domain)
		c.log.Tracef("outbound rerouted: %v => %v",
			consts.OutboundControlPlaneRouting.String(),
			outboundIndex.String(),
		)
	}

	if mark == 0 {
		mark = c.soMarkFromDae
	}

	if int(outboundIndex) >= len(c.outbounds) {
		if len(c.outbounds) == int(consts.OutboundUserDefinedMin) {
			return nil, fmt.Errorf("traffic was dropped due to no-load configuration")
		}
		return nil, fmt.Errorf("outbound id from bpf is out of range: %v not in [0, %v]", outboundIndex, len(c.outbounds)-1)
	}

	outbound := c.outbounds[outboundIndex]
	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr(p.Network),
		IpVersion: consts.IpVersionFromAddr(dst.Addr()),
		IsDns:     false,
	}

	// For UDP, ensure dialer's address family matches client's to prevent
	// "non-IPv4/IPv6 address" errors when writing responses.
	selectionNetworkType := networkType
	if p.Network == "udp" {
		if clientIpVersion := consts.IpVersionFromAddr(src.Addr()); clientIpVersion != networkType.IpVersion {
			selectionNetworkType = &dialer.NetworkType{
				L4Proto:   networkType.L4Proto,
				IpVersion: clientIpVersion,
				IsDns:     false,
			}
		}
	}

	strictIpVersion := dialIp
	d, _, err := outbound.Select(selectionNetworkType, strictIpVersion)
	if err != nil {
		return &proxyDialResult{
				Outbound:             outbound,
				IsDialIp:             strictIpVersion,
				OrigNetworkType:      networkType.StringWithoutDns(),
				SelectionNetworkType: selectionNetworkType.StringWithoutDns(),
			}, fmt.Errorf("select dialer from group %v (orig:%v sel:%v src:%v): %w",
				outbound.Name,
				networkType.StringWithoutDns(),
				selectionNetworkType.StringWithoutDns(),
				p.Src.String(),
				err,
			)
	}

	return &proxyDialResult{
		Outbound:             outbound,
		Dialer:               d,
		DialTarget:           dialTarget,
		Network:              common.MagicNetwork(p.Network, mark, c.mptcp),
		SniffedDomain:        domain,
		Mark:                 mark,
		IsDialIp:             strictIpVersion,
		OrigNetworkType:      networkType.StringWithoutDns(),
		SelectionNetworkType: selectionNetworkType.StringWithoutDns(),
	}, nil
}

func (c *ControlPlane) routeDial(ctx context.Context, p *proxyDialParam) (netproxy.Conn, *proxyDialResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	res, err := c.chooseProxyDialer(ctx, p)
	if err != nil {
		return nil, res, err
	}

	dialCtx, cancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
	defer cancel()

	conn, err := res.Dialer.DialContext(dialCtx, res.Network, res.DialTarget)
	return conn, res, err
}
