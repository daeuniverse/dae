/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestUdpEndpointRouteBindingLifecycle covers the lifetime-bound routing
// result: it must answer only for the bound destination and L4 protocol and
// be replaced by a later update.
func TestUdpEndpointRouteBindingLifecycle(t *testing.T) {
	ue := &UdpEndpoint{}
	dst := netip.MustParseAddrPort("1.1.1.1:443")
	otherDst := netip.MustParseAddrPort("8.8.8.8:53")
	const l4proto = uint8(17)
	const otherL4proto = uint8(6)

	if bound, ok := ue.GetBoundRoutingResult(dst, l4proto); ok || bound != nil {
		t.Fatal("expected empty route binding")
	}

	routingResult := &bpfRoutingResult{Mark: 123, Outbound: 2, Dscp: 10}
	ue.UpdateCachedRoutingResult(dst, l4proto, routingResult)

	bound, ok := ue.GetBoundRoutingResult(dst, l4proto)
	require.True(t, ok)
	require.NotNil(t, bound)
	require.Equal(t, routingResult.Mark, bound.Mark)
	require.Equal(t, routingResult.Outbound, bound.Outbound)
	require.Equal(t, routingResult.Dscp, bound.Dscp)

	if other, ok := ue.GetBoundRoutingResult(otherDst, l4proto); ok || other != nil {
		t.Fatal("route binding matched a different original destination")
	}
	if other, ok := ue.GetBoundRoutingResult(dst, otherL4proto); ok || other != nil {
		t.Fatal("route binding matched a different L4 protocol")
	}

	updated := &bpfRoutingResult{Mark: 77, Outbound: 3, Dscp: 12}
	ue.UpdateCachedRoutingResult(otherDst, l4proto, updated)
	if stale, ok := ue.GetBoundRoutingResult(dst, l4proto); ok || stale != nil {
		t.Fatal("route binding survived being superseded by a new destination")
	}
	bound, ok = ue.GetBoundRoutingResult(otherDst, l4proto)
	require.True(t, ok)
	require.Equal(t, updated.Mark, bound.Mark)
}
