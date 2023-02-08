/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package consts

import "net/netip"

type DialerSelectionPolicy string

const (
	DialerSelectionPolicy_Random                DialerSelectionPolicy = "random"
	DialerSelectionPolicy_Fixed                 DialerSelectionPolicy = "fixed"
	DialerSelectionPolicy_MinAverage10Latencies DialerSelectionPolicy = "min_avg10"
	DialerSelectionPolicy_MinLastLatency        DialerSelectionPolicy = "min"
)

const (
	UdpCheckLookupHost = "connectivitycheck.gstatic.com."
)

type L4ProtoStr string

const (
	L4ProtoStr_TCP L4ProtoStr = "tcp"
	L4ProtoStr_UDP L4ProtoStr = "udp"
)

type IpVersionStr string

const (
	IpVersionStr_4 IpVersionStr = "4"
	IpVersionStr_6 IpVersionStr = "6"
)

func IpVersionFromAddr(addr netip.Addr) IpVersionStr {
	var ipversion IpVersionStr
	switch {
	case addr.Is4() || addr.Is4In6():
		ipversion = IpVersionStr_4
	case addr.Is6():
		ipversion = IpVersionStr_6
	}
	return ipversion
}
