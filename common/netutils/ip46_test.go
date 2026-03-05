/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/stretchr/testify/require"
)

func TestResolveIp46(t *testing.T) {
	direct.InitDirectDialers("223.5.5.5:53")

	t.Run("ipv4_literal", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		ip46, err4, err6 := ResolveIp46(ctx, direct.SymmetricDirect, netip.MustParseAddrPort("223.5.5.5:53"), "1.1.1.1", "udp", false)
		require.NoError(t, err4)
		require.NoError(t, err6)
		require.True(t, ip46.Ip4.IsValid())
		require.False(t, ip46.Ip6.IsValid())
	})

	t.Run("ipv6_literal", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		ip46, err4, err6 := ResolveIp46(ctx, direct.SymmetricDirect, netip.MustParseAddrPort("223.5.5.5:53"), "2001:4860:4860::8888", "udp", false)
		require.NoError(t, err4)
		require.NoError(t, err6)
		require.False(t, ip46.Ip4.IsValid())
		require.True(t, ip46.Ip6.IsValid())
	})
}
