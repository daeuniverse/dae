/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"strings"
	"testing"

	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type chainOrderTestDialer struct {
	name string
	next netproxy.Dialer
}

func (d *chainOrderTestDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	return d.next.DialContext(ctx, network, addr)
}

func registerChainOrderTestScheme(scheme string) {
	D.FromLinkRegister(scheme, func(_ *D.ExtraOption, next netproxy.Dialer, _ string) (netproxy.Dialer, *D.Property, error) {
		return &chainOrderTestDialer{name: scheme, next: next}, &D.Property{
			Name:     scheme,
			Address:  scheme + ".example:443",
			Protocol: scheme,
			Link:     scheme + "://node",
		}, nil
	})
}

func TestNewNetproxyDialerFromLinkBuildsEntryThenExit(t *testing.T) {
	registerChainOrderTestScheme("dae-test-entry")
	registerChainOrderTestScheme("dae-test-exit")
	base := &recordingNetworkDialer{}

	got, property, err := newNetproxyDialerFromLink(base, &D.ExtraOption{},
		"chain: dae-test-entry://node -> dae-test-exit://node")
	if err != nil {
		t.Fatal(err)
	}
	exit, ok := got.(*chainOrderTestDialer)
	if !ok || exit.name != "dae-test-exit" {
		t.Fatalf("outer dialer = %#v, want exit", got)
	}
	adapter, ok := exit.next.(*netConnDialer)
	if !ok {
		t.Fatalf("exit next = %#v, want net.Conn adapter", exit.next)
	}
	entry, ok := adapter.Dialer.(*chainOrderTestDialer)
	if !ok || entry.name != "dae-test-entry" || entry.next != base {
		t.Fatalf("exit next = %#v, want entry over base", exit.next)
	}
	if property.Name != "chain" || property.Protocol != "dae-test-entry->dae-test-exit" ||
		property.Address != "dae-test-entry.example:443->dae-test-exit.example:443" {
		t.Fatalf("unexpected property: %#v", property)
	}
}

func TestNewNetproxyDialerFromLinkRejectsLongChain(t *testing.T) {
	_, _, err := newNetproxyDialerFromLink(&recordingNetworkDialer{}, &D.ExtraOption{},
		"dae-test-entry://a -> dae-test-exit://b -> dae-test-exit://c")
	if err == nil || !strings.Contains(err.Error(), "exactly two nodes") {
		t.Fatalf("err = %v, want two-node chain error", err)
	}
}
