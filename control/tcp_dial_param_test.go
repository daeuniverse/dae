/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestTCPDialParamsPropagateMustToDialResult(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.10:40000")
	dst := netip.MustParseAddrPort("198.51.100.20:443")

	tests := []struct {
		name  string
		param func() *proxyDialParam
	}{
		{
			name: "bpf routing handoff",
			param: func() *proxyDialParam {
				return tcpProxyDialParamFromRoutingResult(&bpfRoutingResult{
					Outbound: uint8(consts.OutboundUserDefinedMin),
					Must:     1,
				}, "example.com", src, dst)
			},
		},
		{
			name: "route dial parameter",
			param: func() *proxyDialParam {
				return (&RouteDialParam{
					Outbound: consts.OutboundUserDefinedMin,
					Must:     true,
					Domain:   "example.com",
					Src:      src,
					Dest:     dst,
				}).toProxyDialParam()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp := newTestDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
			dialParam := tc.param()
			if !dialParam.Must {
				t.Fatal("TCP dial parameter lost must flag")
			}

			result, err := cp.chooseProxyDialer(dialParam)
			if err != nil {
				t.Fatalf("chooseProxyDialer() error = %v", err)
			}
			if !result.Must {
				t.Fatal("TCP dial result lost must flag")
			}
		})
	}
}
