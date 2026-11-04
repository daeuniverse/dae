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
