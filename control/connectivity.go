/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func FormatL4Proto(l4proto uint8) string {
	if l4proto == unix.IPPROTO_TCP {
		return "tcp"
	}
	if l4proto == unix.IPPROTO_UDP {
		return "udp"
	}
	return strconv.Itoa(int(l4proto))
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
		if !isInit || c.log.IsLevelEnabled(logrus.TraceLevel) {
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
		if err := c.bpf.OutboundConnectivityMap.Update(bpfOutboundConnectivityQuery{
			Outbound:  outbound,
			L4proto:   networkType.L4Proto.ToL4Proto(),
			Ipversion: networkType.IpVersion.ToIpVersion(),
		}, value, ebpf.UpdateAny); err != nil {
			c.log.WithFields(logrus.Fields{
				"alive":    alive,
				"network":  networkType.StringWithoutDns(),
				"outbound": c.outboundId2Name[outbound],
			}).Warnf("Failed to notify the kernel program: %v", err)
		}
	}
}
