/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 <mzz@tuta.io>
 */

package control

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
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

func (c *ControlPlaneCore) OutboundAliveChangeCallback(outbound uint8) func(alive bool, l4proto uint8, ipversion uint8) {
	return func(alive bool, l4proto uint8, ipversion uint8) {
		c.log.WithFields(logrus.Fields{
			"alive":       alive,
			"network":     fmt.Sprintf("%v+%v", FormatL4Proto(l4proto), ipversion),
			"outbound_id": outbound,
		}).Tracef("Outbound alive state changed, notify the kernel program.")

		value := uint32(0)
		if alive {
			value = 1
		}
		_ = c.bpf.OutboundConnectivityMap.Update(bpfOutboundConnectivityQuery{
			Outbound:  outbound,
			L4proto:   l4proto,
			Ipversion: ipversion,
		}, value, ebpf.UpdateAny)
	}
}
