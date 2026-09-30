/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"errors"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestGetFirstAliveFollowsOrder(t *testing.T) {
	typ := udpDataNetworkType()
	a := newNamedTestDialer(t, "prio-a")
	b := newNamedTestDialer(t, "prio-b")
	c := newNamedTestDialer(t, "prio-c")
	dialers := []*Dialer{a, b, c}
	set := NewAliveDialerSet(
		a.Log,
		"prio-group",
		typ,
		0,
		consts.DialerSelectionPolicy_Priority,
		dialers,
		[]*Annotation{{HasPriority: true, Priority: 1}, {HasPriority: true, Priority: 2}, {}},
		func(bool) {},
		true,
	)
	for _, d := range dialers {
		d.RegisterAliveDialerSet(set)
	}
	t.Cleanup(func() {
		for _, d := range dialers {
			d.UnregisterAliveDialerSet(set)
		}
	})

	if got := set.GetFirstAlive(nil); got != a {
		t.Fatalf("got %v, want the first ordered dialer", got)
	}
	if got := set.GetFirstAlive(a); got != b {
		t.Fatalf("got %v, want b after excluding a", got)
	}

	a.ReportUnavailableForced(typ, errors.New("offline"))
	if got := set.GetFirstAlive(nil); got != b {
		t.Fatalf("got %v, want b after a died", got)
	}
	b.ReportUnavailableForced(typ, errors.New("offline"))
	if got := set.GetFirstAlive(nil); got != c {
		t.Fatalf("got %v, want c after b died", got)
	}
	c.ReportUnavailableForced(typ, errors.New("offline"))
	if got := set.GetFirstAlive(nil); got != nil {
		t.Fatalf("got %v, want nil when every dialer is dead", got)
	}
}
