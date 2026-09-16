/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
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

// pauseOutboundConnectivityUpdates waits for an in-flight health callback to
// finish before preventing this generation from updating the shared BPF map.
func (c *controlPlaneCore) pauseOutboundConnectivityUpdates() {
	if c == nil {
		return
	}
	c.outboundConnectivityMu.Lock()
	c.outboundConnectivityPaused = true
	c.outboundConnectivityMu.Unlock()
}

// resumeOutboundConnectivityUpdates restores this generation's BPF health
// write ownership unless it has already entered retirement. publish runs while
// callbacks are held out so its snapshot cannot overwrite a newer transition.
func (c *controlPlaneCore) resumeOutboundConnectivityUpdates(publish func()) {
	if c == nil {
		return
	}
	c.outboundConnectivityMu.Lock()
	defer c.outboundConnectivityMu.Unlock()
	if c.retired.Load() {
		return
	}
	c.outboundConnectivityPaused = false
	if publish != nil {
		publish()
	}
}

// markOutboundConnectivityRetired makes a generation permanently ineligible
// to write the shared BPF outbound-connectivity map.
func (c *controlPlaneCore) markOutboundConnectivityRetired() {
	if c == nil {
		return
	}
	c.outboundConnectivityMu.Lock()
	c.retired.Store(true)
	c.outboundConnectivityPaused = true
	c.outboundConnectivityMu.Unlock()
}

// writeOutboundConnectivityLocked updates the shared BPF map. Callers must
// hold outboundConnectivityMu and have established write ownership.
func (c *controlPlaneCore) writeOutboundConnectivityLocked(outbound uint8, alive bool, networkType *dialer.NetworkType) {
	if c == nil || networkType == nil {
		return
	}
	bpf := c.PeekBpf()
	if bpf == nil || bpf.OutboundConnectivityMap == nil {
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
	if err := bpf.OutboundConnectivityMap.Update(key, value, ebpf.UpdateAny); err != nil {
		c.log.WithFields(logrus.Fields{
			"alive":    alive,
			"network":  networkType.StringWithoutDns(),
			"outbound": c.outboundId2Name[outbound],
		}).Warnf("Failed to notify the kernel program: %v", err)
	}
}

// PauseOutboundConnectivityUpdates prevents this generation from updating the
// shared BPF health map while a prepared successor owns the cutover boundary.
func (c *ControlPlane) PauseOutboundConnectivityUpdates() {
	if c == nil || c.core == nil {
		return
	}
	c.core.pauseOutboundConnectivityUpdates()
}

// ResumeOutboundConnectivityUpdates restores this generation's BPF health
// writes and publishes its current selection health as one serialized snapshot.
func (c *ControlPlane) ResumeOutboundConnectivityUpdates() {
	if c == nil || c.core == nil {
		return
	}
	c.resumeOutboundConnectivityUpdates(c.core.writeOutboundConnectivityLocked)
}

func (c *ControlPlane) resumeOutboundConnectivityUpdates(publish func(uint8, bool, *dialer.NetworkType)) {
	c.core.resumeOutboundConnectivityUpdates(func() {
		for outboundID, group := range c.outbounds {
			if group == nil {
				continue
			}
			// Match ordinary callback publication. Random policies and non-IP
			// modes keep kernel admission open for userspace selection/fallback.
			policy := group.GetSelectionPolicy()
			publishHealth := c.dialMode == consts.DialMode_Ip &&
				policy != consts.DialerSelectionPolicy_Random && policy != consts.DialerSelectionPolicy_Fixed
			for _, healthKey := range dialer.StandardHealthKeys() {
				networkType := healthKey.NetworkType()
				alive := true
				if publishHealth {
					if set := group.MustGetAliveDialerSet(networkType); set != nil {
						alive = set.Len() > 0
					}
				}
				publish(uint8(outboundID), alive, networkType)
			}
		}
	})
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
		c.outboundConnectivityMu.Lock()
		defer c.outboundConnectivityMu.Unlock()
		if c.retired.Load() || c.outboundConnectivityPaused {
			return
		}
		c.writeOutboundConnectivityLocked(outbound, alive, networkType)
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
