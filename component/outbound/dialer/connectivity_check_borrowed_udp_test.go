/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

func borrowedUdpTestTypes() (dns, data *NetworkType) {
	return &NetworkType{
			L4Proto:         consts.L4ProtoStr_UDP,
			IpVersion:       consts.IpVersionStr_4,
			IsDns:           true,
			UdpHealthDomain: UdpHealthDomainDns,
		}, &NetworkType{
			L4Proto:         consts.L4ProtoStr_UDP,
			IpVersion:       consts.IpVersionStr_4,
			UdpHealthDomain: UdpHealthDomainData,
		}
}

// TestDnsUdpMarkNotifiesBorrowingDataUdpSet is a regression guard: the
// data-UDP health domain borrows the DNS domain's latency, but it was only ever
// notified while it was still dead (ReportAvailableTraffic gates on
// !MustGetAlive), so its borrowed sorting latency froze at the value captured
// on revival. A DNS-domain mark must now fan out to the same-ipversion data-UDP
// sets.
func TestDnsUdpMarkNotifiesBorrowingDataUdpSet(t *testing.T) {
	dnsType, dataType := borrowedUdpTestTypes()
	d := newNamedTestDialer(t, "p228-borrow")

	dnsSet := NewAliveDialerSet(d.Log, "g", dnsType, 0,
		consts.DialerSelectionPolicy_MinLastLatency, []*Dialer{d}, []*Annotation{{}}, func(bool) {}, true)
	dataSet := NewAliveDialerSet(d.Log, "g", dataType, 0,
		consts.DialerSelectionPolicy_MinLastLatency, []*Dialer{d}, []*Annotation{{}}, func(bool) {}, true)
	d.RegisterAliveDialerSet(dnsSet)
	d.RegisterAliveDialerSet(dataSet)
	t.Cleanup(func() {
		d.UnregisterAliveDialerSet(dnsSet)
		d.UnregisterAliveDialerSet(dataSet)
	})

	// The data-UDP domain is alive and has no latency of its own: its sorting
	// key is the optimistic zero.
	if _, latency := dataSet.GetMinLatency(nil); latency != 0 {
		t.Fatalf("fixture is stale: data-UDP set starts at %v, want the optimistic 0", latency)
	}

	// A DNS probe success of 50ms must reach the data-UDP set as a borrowed
	// latency, even though the data-UDP domain is already alive.
	update, _ := d.markAvailable(dnsType, 50*time.Millisecond)
	d.informDialerGroupUpdate(update)

	got, latency := dataSet.GetMinLatency(nil)
	if got != d {
		t.Fatalf("data-UDP set lost its dialer after the DNS mark: %v", got)
	}
	if latency != 50*time.Millisecond {
		t.Fatalf("borrowed data-UDP latency = %v, want 50ms (frozen borrowed latency)", latency)
	}
}

// TestDnsUdpFanOutUsesDataUdpAliveState pins the other second half: the
// borrowed alive flag must be the data-UDP domain's OWN Alive.Load. Using the
// DNS domain's value (true here) would silently keep a dead data-UDP domain
// alive in the selection sets.
func TestDnsUdpFanOutUsesDataUdpAliveState(t *testing.T) {
	dnsType, dataType := borrowedUdpTestTypes()
	d := newNamedTestDialer(t, "p228-alive")

	dataSet := NewAliveDialerSet(d.Log, "g", dataType, 0,
		consts.DialerSelectionPolicy_MinLastLatency, []*Dialer{d}, []*Annotation{{}}, func(bool) {}, true)
	d.RegisterAliveDialerSet(dataSet)
	t.Cleanup(func() { d.UnregisterAliveDialerSet(dataSet) })

	// The data-UDP domain is dead while the DNS domain is alive.
	d.collectionFineMu.Lock()
	d.mustGetCollection(dataType).Alive.Store(false)
	d.collectionFineMu.Unlock()

	update, _ := d.markAvailable(dnsType, 20*time.Millisecond)
	if !update.alive {
		t.Fatal("fixture is stale: the DNS domain mark must report alive=true")
	}
	if update.borrowedAlive {
		t.Fatal("borrowedAlive must be the data-UDP domain's own state, not the DNS domain's")
	}
	d.informDialerGroupUpdate(update)

	if n := dataSet.Len(); n != 0 {
		t.Fatalf("data-UDP set still holds %d dialer(s) although the data-UDP domain is dead", n)
	}
}

// TestDataUdpMarkHasNoBorrowedFanOut guards against the fan-out turning into a
// loop: a data-UDP mark must not re-notify data-UDP sets through the borrowed
// path (only DNS-domain marks carry a borrow).
func TestDataUdpMarkHasNoBorrowedFanOut(t *testing.T) {
	dnsType, dataType := borrowedUdpTestTypes()
	_ = dnsType
	d := newNamedTestDialer(t, "p228-nofanout")

	dataSet := NewAliveDialerSet(d.Log, "g", dataType, 0,
		consts.DialerSelectionPolicy_MinLastLatency, []*Dialer{d}, []*Annotation{{}}, func(bool) {}, true)
	d.RegisterAliveDialerSet(dataSet)
	t.Cleanup(func() { d.UnregisterAliveDialerSet(dataSet) })

	update, _ := d.markAvailable(dataType, 30*time.Millisecond)
	if len(update.borrowedGroups) != 0 {
		t.Fatalf("a data-UDP mark produced %d borrowed fan-out set(s), want 0", len(update.borrowedGroups))
	}
}
