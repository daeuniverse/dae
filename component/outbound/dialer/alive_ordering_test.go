/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"errors"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

// udpDataNetworkType is a data-plane UDP type: its health domain has no
// periodic probe, so availability notifications are the only membership
// driver and any stale notification would persist.
func udpDataNetworkType() *NetworkType {
	return &NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		IsDns:           false,
		UdpHealthDomain: UdpHealthDomainData,
	}
}

func newOrderingFixture(t *testing.T) (*Dialer, *AliveDialerSet, *NetworkType) {
	t.Helper()
	typ := udpDataNetworkType()
	d := newNamedTestDialer(t, "ordering-node")
	set := NewAliveDialerSet(
		d.Log,
		"ordering-group",
		typ,
		0,
		consts.DialerSelectionPolicy_MinLastLatency,
		[]*Dialer{d},
		[]*Annotation{{}},
		func(bool) {},
		true,
	)
	d.RegisterAliveDialerSet(set)
	t.Cleanup(func() { d.UnregisterAliveDialerSet(set) })
	return d, set, typ
}

// TestNotifyLatencyChangeOrdering verifies that a stale availability
// notification (published after a newer state flip) cannot regress the set
// membership: NotifyLatencyChange must revalidate against the dialer's
// actual collection state.
func TestNotifyLatencyChangeOrdering(t *testing.T) {
	d, set, typ := newOrderingFixture(t)

	// Dialers are assumed alive at construction, so the fresh set carries the
	// member already.
	if set.Len() != 1 {
		t.Fatalf("fresh set must contain the assumed-alive dialer, got %d", set.Len())
	}

	// A stale "dead" notification arriving while the dialer is actually alive
	// must be revalidated away.
	set.NotifyLatencyChange(d, false)
	if set.Len() != 1 {
		t.Fatalf("stale dead notification removed a live dialer; set size %d", set.Len())
	}

	// Real death still removes the dialer...
	d.ReportUnavailableForced(typ, errors.New("forced offline"))
	if set.Len() != 0 {
		t.Fatalf("real death must remove the dialer, set size %d", set.Len())
	}

	// ...and a stale "alive" notification must not resurrect it.
	set.NotifyLatencyChange(d, true)
	if set.Len() != 0 {
		t.Fatalf("stale alive notification resurrected a dead dialer; set size %d", set.Len())
	}

	// Revival through the real traffic path re-adds the dialer.
	d.ReportAvailableTraffic(typ)
	if set.Len() != 1 {
		t.Fatalf("revival must re-add the dialer, set size %d", set.Len())
	}
}

// TestConcurrentAvailabilityNotifications drives concurrent failure and
// success reports on one data-UDP collection and asserts the membership
// converges to the collection state: no stale notification may outlive the
// final state flip (the bug class that could exclude a healthy node until
// the next failure-success cycle).
func TestConcurrentAvailabilityNotifications(t *testing.T) {
	d, set, typ := newOrderingFixture(t)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 1000 {
			// Full traffic-success path (state flip + group notification).
			d.ReportAvailableTraffic(typ)
		}
	}()
	go func() {
		defer wg.Done()
		for range 1000 {
			d.ReportUnavailable(typ, errors.New("dial failed"))
		}
	}()
	wg.Wait()

	// Deterministic final state: kill, then revive through the real traffic
	// path; membership must converge to the collection's alive=true state
	// regardless of the notification ordering history above.
	d.ReportUnavailableForced(typ, errors.New("final offline"))
	if d.MustGetAlive(typ) {
		t.Fatal("collection must be dead after the forced offline")
	}
	if set.Len() != 0 {
		t.Fatalf("membership (%d) diverged from collection state (dead)", set.Len())
	}
	d.ReportAvailableTraffic(typ)
	if !d.MustGetAlive(typ) {
		t.Fatal("collection must be alive after the final traffic success")
	}
	if set.Len() != 1 {
		t.Fatalf("membership (%d) diverged from collection state (alive); a stale dead notification survived", set.Len())
	}
}
