/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/netip"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	commonerrors "github.com/daeuniverse/dae/common/errors"
	ob "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type proxyDialParam struct {
	Outbound    consts.OutboundIndex
	Must        bool
	Domain      string
	Mac         [6]uint8
	Dscp        uint8
	ProcessName [16]uint8
	Src         netip.AddrPort
	Dest        netip.AddrPort
	Mark        uint32
	Network     string         // e.g. "tcp", "udp"
	Excluded    *dialer.Dialer // Dialer to exclude in selection
}

type proxyDialResult struct {
	OutboundIndex           consts.OutboundIndex
	Outbound                *ob.DialerGroup
	Dialer                  *dialer.Dialer
	DialTarget              string
	Network                 string
	Mark                    uint32
	Must                    bool
	SniffedDomain           string
	IsDialIp                bool
	OrigNetworkType         string
	SelectionNetworkType    string
	OrigNetworkTypeObj      *dialer.NetworkType
	SelectionNetworkTypeObj *dialer.NetworkType
	AdmissionNetworkTypeObj *dialer.NetworkType
}

func shouldForceMarkUnavailableOnProxyDialError(err error) bool {
	if err == nil {
		return false
	}
	return commonerrors.IsNetworkUnreachable(err) || commonerrors.IsAddressNotSuitable(err)
}

func notifyProxyDialerHealthCheck(d *dialer.Dialer, l4proto consts.L4ProtoStr, err error) {
	if d == nil || err == nil {
		return
	}
	if commonerrors.IsCanceledOrClosed(err) || !isProxyBackedDialer(d) {
		return
	}
	if l4proto == consts.L4ProtoStr_UDP {
		d.NotifyCheckDnsUdp()
		return
	}
	d.NotifyCheckTcp()
}

func alternateNetworkType(networkType *dialer.NetworkType) *dialer.NetworkType {
	if networkType == nil {
		return nil
	}
	switch networkType.IpVersion {
	case consts.IpVersionStr_4:
		alt := *networkType
		alt.IpVersion = consts.IpVersionStr_6
		return &alt
	case consts.IpVersionStr_6:
		alt := *networkType
		alt.IpVersion = consts.IpVersionStr_4
		return &alt
	default:
		return nil
	}
}

func endpointNetworkTypeForSelection(requestedNetworkType *dialer.NetworkType, admissionNetworkType *dialer.NetworkType) *dialer.NetworkType {
	if requestedNetworkType == nil {
		return nil
	}
	endpointType := *requestedNetworkType
	if admissionNetworkType != nil && admissionNetworkType.IpVersion != "" {
		endpointType.IpVersion = admissionNetworkType.IpVersion
	}
	if endpointType.L4Proto == consts.L4ProtoStr_UDP {
		endpointType.IsDns = false
		endpointType.UdpHealthDomain = dialer.UdpHealthDomainData
	}
	return &endpointType
}

// ErrReservedOutboundReject indicates the resolved outbound is the reserved
// reject index (0xFB). It is not a dialable group: the caller must perform the
// L3 reject action (an ICMP port-unreachable for UDP, used to downgrade QUIC
// to TCP) instead of dialing. Returning this rather than letting the index fall
// through to the out-of-range check is what makes domain-rules that resolve to
// reject behave identically to 4-tuple rules that resolve to reject (both inject
// the ICMP error instead of being silently dropped with an "out of range" error).
var ErrReservedOutboundReject = stderrors.New("reserved outbound reject is handled by the caller, not dialed")

// isReservedOutbound reports whether the resolved outbound index is one of the
// reserved, non-dialable values that the data plane signals via an L3 message
// rather than an actual proxy connection.
func isReservedOutbound(id consts.OutboundIndex) bool {
	return id == consts.OutboundReject
}

func (c *ControlPlane) chooseProxyDialer(p *proxyDialParam) (*proxyDialResult, error) {
	outboundIndex := p.Outbound
	// Reserved outbounds are not real dialer groups. For UDP the reject action
	// is an ICMP port-unreachable (so the client's QUIC stack downgrades to
	// TCP); inject it here so domain-rules that resolve to reject take the same
	// path as 4-tuple rules that resolve to reject. Signal the caller with
	// ErrReservedOutboundReject so it does not try to dial a reserved index.
	if isReservedOutbound(outboundIndex) {
		if p.Network == "udp" {
			if rejectAllowed(p.Src) {
				if e := sendICMPPortUnreachable(p.Src, p.Dest); e != nil {
					c.log.Warnf("reject: failed to inject ICMP port-unreachable to %s: %v", p.Dest, e)
				}
			} else {
				c.log.Debugf("reject: per-client ICMP budget exhausted; silently dropping for %s", p.Src)
			}
			// Mark the flow so later packets of it are dropped in userspace
			// without re-running the routing lookup (see isRejectFlow).
			markRejectFlow(p.Src, p.Dest)
		}
		return nil, ErrReservedOutboundReject
	}
	domain := p.Domain
	src := p.Src
	dst := p.Dest
	mark := p.Mark
	must := p.Must

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
		if outboundIndex, newMark, must, err = c.Route(
			src,
			dst,
			domain,
			proto,
			routingResult,
		); err != nil {
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
		L4Proto:         consts.L4ProtoStr(p.Network),
		IpVersion:       consts.IpVersionFromAddr(dst.Addr()),
		IsDns:           false,
		UdpHealthDomain: dialer.UdpHealthDomainData,
	}

	// For UDP, ensure dialer's address family matches client's to prevent
	// "non-IPv4/IPv6 address" errors when writing responses.
	selectionNetworkType := networkType
	if p.Network == "udp" {
		if clientIpVersion := consts.IpVersionFromAddr(src.Addr()); clientIpVersion != networkType.IpVersion {
			selectionNetworkType = &dialer.NetworkType{
				L4Proto:         networkType.L4Proto,
				IpVersion:       clientIpVersion,
				IsDns:           false,
				UdpHealthDomain: dialer.UdpHealthDomainData,
			}
		}
	}

	strictIpVersion := dialIp
	d, _, admissionNetworkType, err := outbound.SelectWithExclusionResult(selectionNetworkType, strictIpVersion, p.Excluded)
	if stderrors.Is(err, ob.ErrNoAliveDialer) {
		// Fallback for UDP/TCP: if selection failed (probably due to health check fail),
		// try the other IP version if strictIpVersion is not absolutely required by domain routing.
		altType := alternateNetworkType(selectionNetworkType)
		d, _, admissionNetworkType, err = outbound.SelectWithExclusionResult(altType, false, p.Excluded)
		if err == nil {
			selectionNetworkType = altType
		}
	}

	if err != nil {
		return &proxyDialResult{
				OutboundIndex:           outboundIndex,
				Outbound:                outbound,
				Must:                    must,
				IsDialIp:                strictIpVersion,
				OrigNetworkType:         networkType.StringWithoutDns(),
				SelectionNetworkType:    selectionNetworkType.StringWithoutDns(),
				OrigNetworkTypeObj:      networkType,
				SelectionNetworkTypeObj: selectionNetworkType,
				AdmissionNetworkTypeObj: admissionNetworkType,
			}, fmt.Errorf("select dialer from group %v (orig:%v sel:%v src:%v): %w",
				outbound.Name,
				networkType.StringWithoutDns(),
				selectionNetworkType.StringWithoutDns(),
				p.Src.String(),
				err,
			)
	}

	selectionNetworkType = endpointNetworkTypeForSelection(selectionNetworkType, admissionNetworkType)

	return &proxyDialResult{
		OutboundIndex: outboundIndex,
		Outbound:      outbound,
		Dialer:        d,
		DialTarget:    dialTarget,
		Network: func() string {
			if p.Network == "udp" {
				return common.MagicNetworkWithIPVersion(p.Network, mark, c.mptcp, string(selectionNetworkType.IpVersion))
			}
			return common.MagicNetwork(p.Network, mark, c.mptcp)
		}(),
		SniffedDomain:           domain,
		Mark:                    mark,
		Must:                    must,
		IsDialIp:                strictIpVersion,
		OrigNetworkType:         networkType.StringWithoutDns(),
		SelectionNetworkType:    selectionNetworkType.StringWithoutDns(),
		OrigNetworkTypeObj:      networkType,
		SelectionNetworkTypeObj: selectionNetworkType,
		AdmissionNetworkTypeObj: admissionNetworkType,
	}, nil
}

func (c *ControlPlane) routeDial(ctx context.Context, p *proxyDialParam) (netproxy.Conn, *proxyDialResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var lastRes *proxyDialResult
	var lastErr error
	for attempt := range 2 {
		res, err := c.chooseProxyDialer(p)
		if err != nil {
			return nil, res, err
		}
		lastRes = res

		dialCtx, cancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
		conn, err := res.Dialer.DialContext(dialCtx, res.Network, res.DialTarget)
		cancel()
		if err == nil {
			return conn, res, nil
		}
		lastErr = err
		if attempt > 0 || !shouldForceMarkUnavailableOnProxyDialError(err) {
			l4proto := consts.L4ProtoStr(p.Network)
			if res.SelectionNetworkTypeObj != nil {
				l4proto = res.SelectionNetworkTypeObj.L4Proto
			}
			notifyProxyDialerHealthCheck(res.Dialer, l4proto, err)
			return nil, res, err
		}
		if res.SelectionNetworkTypeObj != nil {
			res.Dialer.ReportUnavailableForced(
				res.SelectionNetworkTypeObj,
				fmt.Errorf("proxy dial failed: %w", err),
			)
		}
	}
	return nil, lastRes, lastErr
}
