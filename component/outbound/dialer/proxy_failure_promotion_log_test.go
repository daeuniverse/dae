/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

// proxyFailureNetworkTypes mirrors the fan-out in
// markUnavailableFromProxyFailure: the six transport-domain collections that a
// shared proxy transport failure invalidates.
func proxyFailureNetworkTypes() []*NetworkType {
	return []*NetworkType{
		{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4},
		{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_6},
		{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, UdpHealthDomain: UdpHealthDomainDns, IsDns: true},
		{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_6, UdpHealthDomain: UdpHealthDomainDns, IsDns: true},
		{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, UdpHealthDomain: UdpHealthDomainData},
		{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_6, UdpHealthDomain: UdpHealthDomainData},
	}
}

func proxyFailureWarnCount(hook *test.Hook) int {
	count := 0
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "Marking dialer as unavailable") {
			count++
		}
	}
	return count
}

// TestProxyFailurePromotionLogsOnlyOnStateChange is the Q3 contract: the
// persistent-proxy-IP failure path used to print "Marking dialer as
// unavailable..." at the top of every call, including the calls that found the
// dialer already unavailable. The caller reaches that state repeatedly:
// recordProxyFailure reports the threshold and resets its counter, so a proxy
// that stays dead keeps triggering the promotion. The line must describe a
// state change, and a repeated promotion must stay visible as a count instead
// of disappearing.
func TestProxyFailurePromotionLogsOnlyOnStateChange(t *testing.T) {
	d := newNamedTestDialer(t, "q3-promotion")
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.InfoLevel)
	d.Log = logger

	for _, networkType := range proxyFailureNetworkTypes() {
		if !d.MustGetAlive(networkType) {
			t.Fatalf("precondition: collection %v should start alive", networkType)
		}
	}

	d.markUnavailableFromProxyFailure()

	if got := proxyFailureWarnCount(hook); got != 1 {
		t.Fatalf("first promotion warned %d time(s), want exactly 1", got)
	}
	if got := d.ProxyFailurePromotionCount(); got != 1 {
		t.Fatalf("promotion count after first call = %d, want 1", got)
	}
	for _, networkType := range proxyFailureNetworkTypes() {
		if d.MustGetAlive(networkType) {
			t.Fatalf("collection %v is still alive after the forced promotion", networkType)
		}
	}

	// Second call: the collections are already dead, so the promotion changes
	// nothing and must not warn again.
	hook.Reset()
	d.markUnavailableFromProxyFailure()

	if got := proxyFailureWarnCount(hook); got != 0 {
		t.Fatalf("repeat promotion while already unavailable warned %d time(s), want 0", got)
	}
	if got := d.ProxyFailurePromotionCount(); got != 2 {
		t.Fatalf("promotion count after repeat = %d, want 2 (the repeat is counted, not dropped)", got)
	}

	// The repeat is not silent either: at debug it is reported with the
	// running count.
	logger.SetLevel(logrus.DebugLevel)
	hook.Reset()
	d.markUnavailableFromProxyFailure()
	entries := hook.AllEntries()
	last := entries[len(entries)-1]
	if last.Level != logrus.DebugLevel || !strings.Contains(last.Message, "already unavailable") {
		t.Fatalf("repeat promotion at debug level = %v %q, want a debug line about the repeated promotion", last.Level, last.Message)
	}
	if got := last.Data["promotions"]; got != uint64(3) {
		t.Fatalf("repeat promotion debug line carries promotions=%v, want 3", got)
	}
}

// TestProxyFailurePromotionKeepsTryingToMarkUnavailable guards the other half
// of the Q3 decision: the log line is conditional, the state change is not.
// Skipping ReportUnavailableForced for an already-dead dialer would turn the
// guard into a behaviour change (a collection revived by a health check
// between two promotions would never be re-marked).
func TestProxyFailurePromotionKeepsTryingToMarkUnavailable(t *testing.T) {
	d := newNamedTestDialer(t, "q3-revive")
	logger, _ := test.NewNullLogger()
	logger.SetLevel(logrus.InfoLevel)
	d.Log = logger

	// The dialer reports a latency while alive, which is how a collection
	// comes back between two proxy failures.
	networkType := proxyFailureNetworkTypes()[0]
	d.collectionFineMu.Lock()
	d.mustGetCollection(networkType).Alive.Store(false)
	d.collectionFineMu.Unlock()

	d.markUnavailableFromProxyFailure()
	if d.MustGetAlive(networkType) {
		t.Fatal("forced promotion did not mark the TCP v4 collection unavailable")
	}

	// Revive one collection, as an emergency probe would.
	d.collectionFineMu.Lock()
	d.mustGetCollection(networkType).Alive.Store(true)
	d.collectionFineMu.Unlock()

	d.markUnavailableFromProxyFailure()
	if d.MustGetAlive(networkType) {
		t.Fatal("a revived collection was not re-marked unavailable by the next promotion")
	}
}
