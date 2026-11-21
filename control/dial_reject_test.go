/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

// TestChooseProxyDialerReservedReject is a regression test for the domain-rule
// reject path (PR #1135 review). A domain rule that resolves to the reserved
// reject index (0xFB) used to fall through to the out-of-range range check and
// be silently dropped with an "out of range" error instead of triggering the
// L3 ICMP injection. chooseProxyDialer must now recognise the reserved index
// and return ErrReservedOutboundReject (the caller performs the ICMP action),
// exactly like a 4-tuple rule that resolves to reject.
func TestChooseProxyDialerReservedReject(t *testing.T) {
	if !isReservedOutbound(consts.OutboundReject) {
		t.Fatal("isReservedOutbound(OutboundReject) = false, want true")
	}
	if isReservedOutbound(consts.OutboundDirect) {
		t.Fatal("isReservedOutbound(OutboundDirect) = true, want false")
	}

	// A minimal ControlPlane is enough: the reserved-outbound short-circuit
	// returns before any dialer/group state is touched.
	c := &ControlPlane{}
	p := &proxyDialParam{
		Outbound: consts.OutboundReject,
		Network:  "tcp",
		Src:      netip.MustParseAddrPort("192.0.2.10:41000"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
	}
	if _, err := c.chooseProxyDialer(p); !stderrors.Is(err, ErrReservedOutboundReject) {
		t.Fatalf("chooseProxyDialer(reject) error = %v, want ErrReservedOutboundReject", err)
	}
}
