/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

const (
	outboundConnectivitySlotsPerDomain   = uint32(2)
	outboundConnectivityDomainTCP        = uint32(0)
	outboundConnectivityDomainDnsUDP     = uint32(1)
	outboundConnectivityDomainDataUDP    = uint32(2)
	outboundConnectivitySlotsPerOutbound = outboundConnectivitySlotsPerDomain * 3
)

func FormatL4Proto(l4proto uint8) string {
	if l4proto == consts.IPPROTO_TCP {
		return "tcp"
	}
	if l4proto == consts.IPPROTO_UDP {
		return "udp"
	}
	return strconv.Itoa(int(l4proto))
}

func outboundConnectivityDomainIndex(networkType *dialer.NetworkType) uint32 {
	if networkType.L4Proto != consts.L4ProtoStr_UDP {
		return outboundConnectivityDomainTCP
	}
	if networkType.EffectiveUdpHealthDomain() == dialer.UdpHealthDomainDns {
		return outboundConnectivityDomainDnsUDP
	}
	return outboundConnectivityDomainDataUDP
}

func outboundConnectivityMapKey(outbound uint8, networkType *dialer.NetworkType) uint32 {
	domainIdx := outboundConnectivityDomainIndex(networkType)
	ipVersionIdx := uint32(0)
	if networkType.IpVersion == consts.IpVersionStr_6 {
		ipVersionIdx = 1
	}
	return uint32(outbound)*outboundConnectivitySlotsPerOutbound + domainIdx*outboundConnectivitySlotsPerDomain + ipVersionIdx
}

func (c *controlPlaneCore) outboundAliveChangeCallback(outbound uint8, dryrun bool) func(alive bool, networkType *dialer.NetworkType, isInit bool) {
	return func(alive bool, networkType *dialer.NetworkType, isInit bool) {
		select {
		case <-c.closed.Done():
			return
		default:
		}
		if !isInit && dryrun {
			return
		}
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			strAlive := "NOT ALIVE"
			if alive {
				strAlive = "ALIVE"
			}
			c.log.WithFields(logrus.Fields{
				"outboundId": outbound,
			}).Tracef("Outbound <%v> %v -> %v, notify the kernel program.", c.outboundId2Name[outbound], networkType.StringWithoutDns(), strAlive)
		}

		value := uint32(0)
		if alive {
			value = 1
		}
		// ARRAY map key: outbound_id * 6 + domain * 2 + ipversion
		// domain: 0=TCP, 1=DNS UDP, 2=data UDP; ipversion: 0=IPv4, 1=IPv6
		key := outboundConnectivityMapKey(outbound, networkType)
		if err := c.bpf.OutboundConnectivityMap.Update(key, value, ebpf.UpdateAny); err != nil {
			c.log.WithFields(logrus.Fields{
				"alive":    alive,
				"network":  networkType.StringWithoutDns(),
				"outbound": c.outboundId2Name[outbound],
			}).Warnf("Failed to notify the kernel program: %v", err)
		}
	}
}

func (c *controlPlaneCore) dialerAliveTransitionCallback(d *dialer.Dialer) func(networkType *dialer.NetworkType, alive bool) {
	return func(networkType *dialer.NetworkType, alive bool) {
		if alive || d == nil || networkType == nil || networkType.L4Proto != consts.L4ProtoStr_UDP {
			return
		}
		// DNS UDP health transitions must not directly invalidate generic UDP
		// endpoints. DNS fast path uses a separate forwarder/cache lifecycle,
		// while pooled data-plane UDP endpoints serve non-DNS traffic.
		if networkType.EffectiveUdpHealthDomain() == dialer.UdpHealthDomainDns {
			return
		}
		removed := DefaultUdpEndpointPool.InvalidateDialerNetworkType(d, networkType)
		if removed == 0 || !c.log.IsLevelEnabled(logrus.DebugLevel) {
			return
		}
		c.log.WithFields(logrus.Fields{
			"dialer":  d.Property().Name,
			"network": networkType.String(),
			"removed": removed,
		}).Debug("Invalidated probing UDP endpoints after dialer transitioned to not alive")
	}
}
