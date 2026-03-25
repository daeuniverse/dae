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

func FormatL4Proto(l4proto uint8) string {
	if l4proto == consts.IPPROTO_TCP {
		return "tcp"
	}
	if l4proto == consts.IPPROTO_UDP {
		return "udp"
	}
	return strconv.Itoa(int(l4proto))
}

func outboundConnectivityMapKey(outbound uint8, networkType *dialer.NetworkType) uint32 {
	protoIdx := uint32(0)
	if networkType.L4Proto == consts.L4ProtoStr_UDP {
		protoIdx = 1
	}
	ipVersionIdx := uint32(0)
	if networkType.IpVersion == consts.IpVersionStr_6 {
		ipVersionIdx = 1
	}
	return uint32(outbound)*4 + protoIdx*2 + ipVersionIdx
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
		// ARRAY map key: outbound_id * 4 + l4proto * 2 + ipversion
		// l4proto: 0=TCP, 1=UDP; ipversion: 0=IPv4, 1=IPv6
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
