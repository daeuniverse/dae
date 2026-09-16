/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"net"
	"testing"

	_ "github.com/daeuniverse/outbound/dialer/shadowsocks"
	_ "github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/sirupsen/logrus"
)

// mustStayAlive asserts the dialer is alive for typ and fails otherwise.
func mustStayAlive(t *testing.T, d *Dialer, typ *NetworkType, stage string) {
	t.Helper()
	if !d.MustGetAlive(typ) {
		t.Fatalf("%s: dialer should stay alive, but was marked unavailable", stage)
	}
}

// TestCheck_CheckOptionFailureKeepsAlive verifies that a check-option build
// failure (e.g. the shared check URL cannot be resolved via the system
// resolver) is probe-infrastructure trouble, not node trouble: the dialer's
// health state must be preserved instead of flapping the whole fleet.
func TestCheck_CheckOptionFailureKeepsAlive(t *testing.T) {
	d := newNamedTestDialer(t, "opt-fail-node")
	typ := newTestNetworkType()

	opts := &CheckOption{
		networkType: typ,
		CheckFunc: func(ctx context.Context, typ *NetworkType) (bool, error) {
			return false, wrapCheckOptionError(fmt.Errorf("failed to parse tcp_check_url: resolve refused"))
		},
	}
	if _, err := d.check(opts, false, nil); err == nil {
		t.Fatal("expected the underlying error to be propagated")
	}
	mustStayAlive(t, d, typ, "after option-unavailable failure")
}

// TestCheck_TeardownClosedErrorKeepsAlive verifies that teardown-style
// "closed connection" errors from a probe racing dialer retirement do not
// mark the node unavailable (and thus do not poison the process-global proxy
// failure tracker via NotifyHealthCheckResult).
func TestCheck_TeardownClosedErrorKeepsAlive(t *testing.T) {
	d := newNamedTestDialer(t, "teardown-node")
	typ := newTestNetworkType()

	// Retire the dialer so the closed error races a real shutdown.
	d.RetireForEstablishedFlows()
	if d.ctx.Err() == nil {
		t.Fatal("setup: dialer context should be canceled after retirement")
	}

	opts := &CheckOption{
		networkType: typ,
		CheckFunc: func(ctx context.Context, typ *NetworkType) (bool, error) {
			return false, fmt.Errorf("dial proxy: %w", net.ErrClosed)
		},
	}
	if _, err := d.check(opts, false, nil); err == nil {
		t.Fatal("expected the underlying error to be propagated")
	}
	mustStayAlive(t, d, typ, "after teardown-style failure")
}

// TestCheck_ClosedErrorWhileAliveMarksUnavailable pins the tightened teardown
// predicate: a closed-connection error observed while the dialer is still
// live is node evidence, not teardown. Mux protocols in the outbound fork
// (anytls, juicity, ...) surface net.ErrClosed when the remote side kills
// the session, so punishing here is what lets a dead mux node be detected.
func TestCheck_ClosedErrorWhileAliveMarksUnavailable(t *testing.T) {
	d := newNamedTestDialer(t, "mux-death-node")
	typ := newTestNetworkType()

	opts := &CheckOption{
		networkType: typ,
		CheckFunc: func(ctx context.Context, typ *NetworkType) (bool, error) {
			return false, fmt.Errorf("dial proxy: %w", net.ErrClosed)
		},
	}
	if _, err := d.check(opts, false, nil); err == nil {
		t.Fatal("expected the underlying error to be propagated")
	}
	if d.MustGetAlive(typ) {
		t.Fatal("closed connection while the dialer is live is node evidence " +
			"(e.g. remote mux session death) and should mark the dialer unavailable")
	}
}

// TestCheck_RealNodeFailureMarksUnavailable is the control case: a genuine
// probe failure must still mark the dialer unavailable, so the skip rules
// above cannot mask real outages.
func TestCheck_RealNodeFailureMarksUnavailable(t *testing.T) {
	d := newNamedTestDialer(t, "real-fail-node")
	typ := newTestNetworkType()

	opts := &CheckOption{
		networkType: typ,
		CheckFunc: func(ctx context.Context, typ *NetworkType) (bool, error) {
			return false, fmt.Errorf("connection refused")
		},
	}
	if _, err := d.check(opts, false, nil); err == nil {
		t.Fatal("expected the underlying error to be propagated")
	}
	if d.MustGetAlive(typ) {
		t.Fatal("genuine probe failure should mark the dialer unavailable")
	}
}

// TestNewFromLinkContext_IndependentProxyIpCaches verifies that two dialers
// created from links sharing the same proxy address own independent sticky-IP
// caches. A shared cache keyed by proxy address is thrashed by per-dialer
// check cycles (each dialer labels the shared entry with its own cycle, so
// every lookup of the other dialer misses), silently disabling stickiness.
func TestNewFromLinkContext_IndependentProxyIpCaches(t *testing.T) {
	log := logrus.New()
	option := &GlobalOption{
		Log:           log,
		CheckInterval: 0,
	}
	link := "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@sticky.example.com:8388#node"

	d1, err := NewFromLinkContext(context.Background(), option, InstanceOption{}, link, "sub1")
	if err != nil {
		t.Fatalf("parse link: %v", err)
	}
	d2, err := NewFromLinkContext(context.Background(), option, InstanceOption{}, link, "sub1")
	if err != nil {
		t.Fatalf("parse link: %v", err)
	}
	t.Cleanup(func() {
		_ = d1.Close()
		_ = d2.Close()
	})

	if d1.property.Address != d2.property.Address {
		t.Fatalf("test premise: expected equal proxy addresses, got %q vs %q",
			d1.property.Address, d2.property.Address)
	}
	if d1.proxyIpCache == nil || d2.proxyIpCache == nil {
		t.Fatal("sticky-wrapped dialers must own a proxy IP cache")
	}
	if d1.proxyIpCache == d2.proxyIpCache {
		t.Fatal("dialers sharing a proxy address must not share one sticky-IP cache; " +
			"per-dialer check cycles would defeat each other's entries")
	}
}

// TestProxyIpCacheRegistry_RefcountSymmetry pins the registry accounting that
// RetireForEstablishedFlows relies on: unregister decrements the per-cache
// refcount, so a cache shared by several dialers (e.g. the clone fallback
// path in CloneWithGlobalOptionContext) stays registered — and keeps
// receiving invalidations — until every sharer has retired.
func TestProxyIpCacheRegistry_RefcountSymmetry(t *testing.T) {
	resetGlobalProxyState()
	t.Cleanup(resetGlobalProxyState)

	const addr = "refcount.example.com:443"
	cache := NewProxyIpCache()

	registerProxyCache(addr, cache)
	registerProxyCache(addr, cache) // second sharer (clone fallback shape)

	globalProxyIpCacheRegistry.Lock()
	if got := globalProxyIpCacheRegistry.caches[addr][cache]; got != 2 {
		globalProxyIpCacheRegistry.Unlock()
		t.Fatalf("after two registers: refcount = %d, want 2", got)
	}
	globalProxyIpCacheRegistry.Unlock()

	// First sharer retires: the cache must remain visible to invalidation.
	unregisterProxyCache(addr, cache)
	globalProxyIpCacheRegistry.Lock()
	_, stillRegistered := globalProxyIpCacheRegistry.caches[addr][cache]
	globalProxyIpCacheRegistry.Unlock()
	if !stillRegistered {
		t.Fatal("one unregister of a twice-registered cache must not remove it; " +
			"a still-live sibling would lose cache invalidation")
	}

	// Last sharer retires: the entry is gone.
	unregisterProxyCache(addr, cache)
	globalProxyIpCacheRegistry.Lock()
	_, stillRegistered = globalProxyIpCacheRegistry.caches[addr][cache]
	globalProxyIpCacheRegistry.Unlock()
	if stillRegistered {
		t.Fatal("after the last unregister the cache entry should be removed")
	}
}
