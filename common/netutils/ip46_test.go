/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol/direct"
)

func TestResolveIp46(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ip46, err4, err6 := ResolveIp46(ctx, direct.SymmetricDirect, netip.MustParseAddrPort("223.5.5.5:53"), "www.apple.com", "udp", false)
	if err4 != nil || err6 != nil {
		t.Fatal(err4, err6)
	}
	if !ip46.Ip4.IsValid() && !ip46.Ip6.IsValid() {
		t.Fatal("No record")
	}
}
