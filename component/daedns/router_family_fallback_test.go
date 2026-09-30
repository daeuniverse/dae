/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package daedns

import (
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/netutils"
)

func TestIpAddrsFromIp46FamilyFallback(t *testing.T) {
	v4 := netip.MustParseAddr("103.190.178.214")
	v6 := netip.MustParseAddr("2407:d840:20:0:be24:11ff:fe68:23dd")
	only4 := &netutils.Ip46{Ip4: v4}
	only6 := &netutils.Ip46{Ip6: v6}
	both := &netutils.Ip46{Ip4: v4, Ip6: v6}

	cases := []struct {
		name   string
		ip46   *netutils.Ip46
		family string
		want   []net.IP
	}{
		{"v4 request, v4 present", both, "4", []net.IP{net.IP(v4.AsSlice())}},
		{"v6 request, v6 present", both, "6", []net.IP{net.IP(v6.AsSlice())}},
		{"v4 request falls back to v6", only6, "4", []net.IP{net.IP(v6.AsSlice())}},
		{"v6 request falls back to v4", only4, "6", []net.IP{net.IP(v4.AsSlice())}},
		{"any request, both present", both, "", []net.IP{net.IP(v4.AsSlice()), net.IP(v6.AsSlice())}},
		{"nil resolver", nil, "4", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ipAddrsFromIp46(tc.ip46, tc.family)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v addrs, want %v", got, tc.want)
			}
			for i := range got {
				if !got[i].IP.Equal(tc.want[i]) {
					t.Errorf("addr[%d] = %v, want %v", i, got[i].IP, tc.want[i])
				}
			}
		})
	}
}
