/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"net"
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/errors"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
)

type udpLifecycleContext struct {
	dialer      *componentdialer.Dialer
	networkType componentdialer.NetworkType
	profile     UdpLifecycleProfile
}

func newDnsUdpLifecycleContext(dialArg *dialArgument, profile UdpLifecycleProfile) (udpLifecycleContext, bool) {
	if dialArg == nil || dialArg.bestDialer == nil || dialArg.l4proto != consts.L4ProtoStr_UDP {
		return udpLifecycleContext{}, false
	}
	if profile.Kind == 0 {
		profile = newDnsLifecycleProfile(dialArg.bestDialer)
	}
	return udpLifecycleContext{
		dialer: dialArg.bestDialer,
		networkType: componentdialer.NetworkType{
			L4Proto:         consts.L4ProtoStr_UDP,
			IpVersion:       dialArg.ipversion,
			IsDns:           profile.HealthDomain == componentdialer.UdpHealthDomainDns,
			UdpHealthDomain: profile.HealthDomain,
		},
		profile: profile,
	}, true
}

func newUdpSessionLifecycleContext(ue *UdpEndpoint, fallbackIpVersion consts.IpVersionStr) (udpLifecycleContext, bool) {
	if ue == nil || ue.Dialer == nil {
		return udpLifecycleContext{}, false
	}
	profile := ue.lifecycleProfile
	if profile.Kind == 0 {
		profile = newDataSessionLifecycleProfile(ue.Dialer)
	}
	networkType := udpEndpointNetworkType(ue)
	networkType.L4Proto = consts.L4ProtoStr_UDP
	networkType.IsDns = profile.HealthDomain == componentdialer.UdpHealthDomainDns
	networkType.UdpHealthDomain = profile.HealthDomain
	if networkType.IpVersion == "" {
		switch {
		case ue.lAddr.IsValid():
			networkType.IpVersion = consts.IpVersionFromAddr(ue.lAddr.Addr())
		case ue.poolKey.Src.IsValid():
			networkType.IpVersion = consts.IpVersionFromAddr(ue.poolKey.Src.Addr())
		case ue.poolKey.Dst.IsValid():
			networkType.IpVersion = consts.IpVersionFromAddr(ue.poolKey.Dst.Addr())
		default:
			networkType.IpVersion = fallbackIpVersion
		}
	}
	return udpLifecycleContext{
		dialer:      ue.Dialer,
		networkType: networkType,
		profile:     profile,
	}, true
}

func newUdpDialOptionLifecycleContext(dialOption *DialOption, src netip.AddrPort) (udpLifecycleContext, bool) {
	if dialOption == nil || dialOption.Dialer == nil {
		return udpLifecycleContext{}, false
	}
	profile := newDataSessionLifecycleProfile(dialOption.Dialer)
	networkType := componentdialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionFromAddr(src.Addr()),
		UdpHealthDomain: profile.HealthDomain,
	}
	if dialOption.NetworkType != nil {
		networkType = *dialOption.NetworkType
	}
	networkType.L4Proto = consts.L4ProtoStr_UDP
	networkType.IsDns = false
	networkType.UdpHealthDomain = profile.HealthDomain
	return udpLifecycleContext{
		dialer:      dialOption.Dialer,
		networkType: networkType,
		profile:     profile,
	}, true
}

func (c udpLifecycleContext) reportTrafficSuccess() {
	if c.dialer == nil {
		return
	}
	c.dialer.ReportAvailableTraffic(&c.networkType)
}

func (c udpLifecycleContext) reportUnavailable(err error) {
	if c.dialer == nil {
		return
	}
	if c.profile.Kind == UdpLifecycleKindDnsTransactional {
		c.dialer.ReportUnavailableTransactional(&c.networkType, err)
		return
	}
	c.dialer.ReportUnavailable(&c.networkType, err)
}

func (c udpLifecycleContext) reportUnavailableForced(err error) {
	if c.dialer == nil {
		return
	}
	c.dialer.ReportUnavailableForced(&c.networkType, err)
}

func (c udpLifecycleContext) shouldDiscardPooledConnOnTimeout(err error) bool {
	if c.profile.Kind == 0 || !c.profile.DiscardPooledConnOnTimeout || err == nil {
		return false
	}
	var netErr net.Error
	return stderrors.As(err, &netErr) && netErr.Timeout()
}

func (c udpLifecycleContext) shouldRetireOnNormalClose(err error) bool {
	if c.profile.Kind == 0 || !c.profile.RetireOnNormalClose {
		return false
	}
	return errors.IsUDPEndpointNormalClose(err)
}

func (c udpLifecycleContext) handleReply(ue *UdpEndpoint, nowNano int64) {
	if ue == nil {
		return
	}
	if c.profile.PromoteOnReply {
		ue.markReplied(nowNano)
	}
	if c.profile.StickyAfterReply {
		c.reportTrafficSuccess()
	}
}
