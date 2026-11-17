/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"testing"

	"github.com/daeuniverse/dae/common/subscription"
	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func TestFindNodeByNameAndProvider(t *testing.T) {
	subProvider := "p_sub"
	nodes := []nativeapi.Node{
		{ID: "sub-id", Name: "edge", ProviderID: &subProvider},
		{ID: "inline-id", Name: "edge"},
	}
	node := findNodeByNameAndProvider(nodes, "edge", inlineProviderID)
	if node == nil || node.ID != "inline-id" {
		t.Fatalf("inline node = %+v, want the inline duplicate", node)
	}
	if node = findNodeByNameAndProvider(nodes, "edge", subProvider); node == nil || node.ID != "sub-id" {
		t.Fatalf("subscription node = %+v, want the subscription duplicate", node)
	}
}

// An untagged subscription must report its own provider. Before the fix its
// nodes carried the inline identity, so DELETE /nodes edited node.dae and
// /providers counted them as inline.
func TestUntaggedSubscriptionNodeHasOwnProvider(t *testing.T) {
	option := &dialer.GlobalOption{Log: logrus.New()}
	link := "socks5://user:pass@203.0.113.10:1080"

	// The inline node: no subscription tag, no provider tag.
	inline, err := dialer.NewFromLinkContext(context.Background(), option, dialer.InstanceOption{DisableCheck: true}, link, "")
	if err != nil {
		t.Fatalf("inline dialer: %v", err)
	}
	defer func() { _ = inline.Close() }()
	if got := providerIDOf(inline.Property().ProviderTag); got != inlineProviderID {
		t.Fatalf("inline provider id = %q, want %q", got, inlineProviderID)
	}

	// The same link delivered by an untagged subscription: still tagless for
	// subtag() filters, but its own provider identity.
	providerKey := subscription.ProviderKey("", "http://127.0.0.1:18080/u")
	if providerKey == "" {
		t.Fatal("an untagged subscription needs a non-empty provider key")
	}
	sub, err := dialer.NewFromLinkContext(context.Background(), option, dialer.InstanceOption{DisableCheck: true}, link, "")
	if err != nil {
		t.Fatalf("subscription dialer: %v", err)
	}
	defer func() { _ = sub.Close() }()
	sub.SetProviderTag(providerKey)

	if got := sub.Property().SubscriptionTag; got != "" {
		t.Fatalf("subtag() sees %q, want the untagged subscription to stay tagless", got)
	}
	if got := providerIDOf(sub.Property().ProviderTag); got == inlineProviderID {
		t.Fatalf("untagged subscription still reports the inline provider %q", got)
	}
	if got, want := providerNameOf(providerKey, ""), providerKey; got != want {
		t.Fatalf("provider name = %q, want %q", got, want)
	}
}
