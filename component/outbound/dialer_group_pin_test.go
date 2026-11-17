/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

// A runtime pin keeps the transport admitted: userspace dials the chosen member
// even when probe health says the group has no alive member, so kernel admission
// must not close. admissionAlive is the rule the alive-change callback applies;
// before the fix only the publish path consulted the pin, so a health
// notification could still write 0 and drop the flow before userspace ran.
func TestPinnedTransportKeepsAdmissionOpen(t *testing.T) {
	option := &dialer.GlobalOption{Log: log}
	d := newDirectDialer(option)
	g := &DialerGroup{log: log, Name: "pinned", Dialers: []*dialer.Dialer{d}}
	// NewDialerGroup starts every transport unpinned (-1); a hand-built fixture
	// has to publish the same snapshot or slot 0 reads as "pinned to member 0".
	g.selection.Store(&dialerSelection{overrides: [2]int64{-1, -1}})

	udp := TestDataUdp4NetworkType
	tcp := &dialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}

	if g.admissionAlive(false, udp) {
		t.Fatal("without a pin, health decides admission")
	}
	if _, err := g.SetOverride(SelectionNetworkUDP, 0); err != nil {
		t.Fatalf("pin: %v", err)
	}
	if !g.admissionAlive(false, udp) {
		t.Fatal("a pinned UDP transport must stay admitted when health is empty")
	}
	if g.admissionAlive(false, tcp) {
		t.Fatal("the pin is per transport: TCP must still follow health")
	}
	if !g.admissionAlive(true, tcp) {
		t.Fatal("a healthy transport stays admitted")
	}
}
