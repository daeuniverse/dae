/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

// parseFailureCountOf reads the running dropped-node count under the set's own
// mutex. The production code no longer exposes an accessor for it: the counter
// is an implementation detail of the batched warning above.
func parseFailureCountOf(s *DialerSet) uint64 {
	s.parseFailuresMu.Lock()
	defer s.parseFailuresMu.Unlock()
	return s.parseFailures
}

// TestSkippedSubscriptionNodesWarnOnceThenAggregate is the Q4 contract. A node
// whose link cannot be parsed is dropped from the dialer set, so it can never
// be selected by any routing rule -- that is an anomaly, not a milestone, and
// it used to be logged at info. A subscription refresh can invalidate many
// nodes at once, so the first drop warns with the concrete parse error and one
// aggregate line closes the build with the per-subscription totals.
func TestSkippedSubscriptionNodesWarnOnceThenAggregate(t *testing.T) {
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.WarnLevel)

	option := &dialer.GlobalOption{Log: logger, CheckInterval: time.Minute}
	set := NewDialerSetFromLinksContext(context.Background(), option, map[string][]string{
		"sub-a": {"q4-unknown-scheme://one", "q4-unknown-scheme://two"},
		"sub-b": {"q4-unknown-scheme://three"},
	})
	t.Cleanup(func() { _ = set.Close() })

	entries := hook.AllEntries()
	if len(entries) != 2 {
		t.Fatalf("dropped nodes emitted %d warning(s), want 2 (first drop + aggregate):\n%s",
			len(entries), formatOutboundEntries(entries))
	}

	first := entries[0]
	if first.Level != logrus.WarnLevel {
		t.Fatalf("first dropped node level = %v, want warn (a dropped node changes routing)", first.Level)
	}
	if !strings.Contains(first.Message, "failed to parse node") {
		t.Fatalf("first dropped node message = %q, want the parse failure", first.Message)
	}
	if !strings.Contains(first.Message, "will not participate in routing") {
		t.Fatalf("first dropped node message = %q, want the routing consequence spelled out", first.Message)
	}

	summary := entries[1]
	if summary.Level != logrus.WarnLevel {
		t.Fatalf("aggregate level = %v, want warn", summary.Level)
	}
	if !strings.Contains(summary.Message, "3 node(s) were skipped") {
		t.Fatalf("aggregate message = %q, want the total dropped count", summary.Message)
	}
	if !strings.Contains(summary.Message, "sub-a=2") || !strings.Contains(summary.Message, "sub-b=1") {
		t.Fatalf("aggregate message = %q, want the per-subscription breakdown", summary.Message)
	}
	if got := parseFailureCountOf(set); got != 3 {
		t.Fatalf("parse failure count = %d, want 3", got)
	}
	if got := len(set.AllDialers()); got != 0 {
		t.Fatalf("DialerSet holds %d dialer(s) for three unparsable nodes, want 0", got)
	}
}

// TestValidSubscriptionNodesAreSilent keeps the aggregate honest: a clean
// subscription produces no warning and no aggregate line.
func TestValidSubscriptionNodesAreSilent(t *testing.T) {
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.WarnLevel)

	option := &dialer.GlobalOption{Log: logger, CheckInterval: time.Minute}
	set := NewDialerSetFromLinksContext(context.Background(), option, map[string][]string{
		"sub-ok": {"socks5://user:pass@203.0.113.10:1080"},
	})
	t.Cleanup(func() { _ = set.Close() })

	if got := len(hook.AllEntries()); got != 0 {
		t.Fatalf("a clean subscription emitted %d warning(s), want 0:\n%s", got, formatOutboundEntries(hook.AllEntries()))
	}
	if got := parseFailureCountOf(set); got != 0 {
		t.Fatalf("parse failure count = %d, want 0", got)
	}
	if got := len(set.AllDialers()); got != 1 {
		t.Fatalf("DialerSet holds %d dialer(s), want 1", got)
	}
}

// TestSkippedNodeDetailStaysAvailableAtDebug checks that the aggregate does not
// swallow the individual causes: every later drop keeps its own error at debug.
func TestSkippedNodeDetailStaysAvailableAtDebug(t *testing.T) {
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)

	option := &dialer.GlobalOption{Log: logger, CheckInterval: time.Minute}
	set := NewDialerSetFromLinksContext(context.Background(), option, map[string][]string{
		"sub-a": {"q4-unknown-scheme://one", "q4-unknown-scheme://two"},
	})
	t.Cleanup(func() { _ = set.Close() })

	detailed := 0
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.DebugLevel && strings.Contains(entry.Message, "failed to parse node") {
			detailed++
		}
	}
	if detailed != 1 {
		t.Fatalf("per-node failure detail at debug = %d line(s), want 1 (the drops after the first)", detailed)
	}
}

func formatOutboundEntries(entries []*logrus.Entry) string {
	var b strings.Builder
	for _, entry := range entries {
		b.WriteString(entry.Level.String())
		b.WriteString(": ")
		b.WriteString(entry.Message)
		b.WriteByte('\n')
	}
	return b.String()
}
