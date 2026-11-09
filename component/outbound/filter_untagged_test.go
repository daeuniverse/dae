/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

// An untagged subscription is owned by its provider key but stays tagless for
// subtag(), so `subtag(regex: '^$')` keeps matching it.
func TestUntaggedSubscriptionKeepsEmptyDisplayTag(t *testing.T) {
	option := &dialer.GlobalOption{Log: logrus.New(), CheckInterval: time.Minute}
	const key = "sub_abc"
	set := NewDialerSetFromLinksContext(context.Background(), option, map[string][]string{
		key: {"socks5://127.0.0.1:1080#n"},
	}, map[string]string{key: ""})
	t.Cleanup(func() { _ = set.Close() })

	if len(set.dialers) != 1 {
		t.Fatalf("dialers = %d, want 1", len(set.dialers))
	}
	d := set.dialers[0]
	if got := set.nodeToTagMap[d]; got != "" {
		t.Fatalf("display tag = %q, want empty", got)
	}
	if got := set.ParseReport(map[string][]string{key: {"x"}})[key]; got.Parsed != 1 {
		t.Fatalf("parsed for provider key = %d, want 1", got.Parsed)
	}
}

// TestDialerOrderIsDeterministic pins the member order that `fixed(n)` and
// `select(n)` index into: the same configuration must resolve index n to the
// same node on every build, or a runtime selection silently points at a
// different node after each reload.
func TestDialerOrderIsDeterministic(t *testing.T) {
	option := &dialer.GlobalOption{Log: logrus.New(), CheckInterval: time.Minute}
	links := map[string][]string{
		"":      {"socks5://127.0.0.1:1080#inline-a"},
		"sub-b": {"socks5://127.0.0.1:2080#b-1", "socks5://127.0.0.1:2081#b-2"},
		"sub-a": {"socks5://127.0.0.1:3080#a-1"},
	}
	order := func() []string {
		set := NewDialerSetFromLinksContext(context.Background(), option, links, nil)
		t.Cleanup(func() { _ = set.Close() })
		names := make([]string, 0, len(set.dialers))
		for _, d := range set.dialers {
			names = append(names, d.Property().Name)
		}
		return names
	}
	want := []string{"inline-a", "a-1", "b-1", "b-2"}
	for i := 0; i < 8; i++ {
		got := order()
		if len(got) != len(want) {
			t.Fatalf("dialers = %v, want %v", got, want)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("build %d order = %v, want %v", i, got, want)
			}
		}
	}
}
