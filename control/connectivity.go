/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/component/outbound/dialer"
	"golang.org/x/sys/unix"
	"strconv"
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

func (c *controlPlaneCore) OutboundAliveChangeCallback(outbound uint8) func(alive bool, networkType *dialer.NetworkType) {
	return func(alive bool, networkType *dialer.NetworkType) {
		c.log.WithFields(logrus.Fields{
			"alive":    alive,
			"network":  networkType.StringWithoutDns(),
			"outbound": c.outboundId2Name[outbound],
		}).Warnf("Outbound alive state changed, notify the kernel program.")

		value := uint32(0)
		if alive {
			value = 1
		}
		_ = c.bpf.OutboundConnectivityMap.Update(bpfOutboundConnectivityQuery{
			Outbound:  outbound,
			L4proto:   networkType.L4Proto.ToL4Proto(),
			Ipversion: networkType.IpVersion.ToIpVersion(),
		}, value, ebpf.UpdateAny)
	}
}
