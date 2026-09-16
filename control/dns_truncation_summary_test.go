/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

// These tests pin the operational outlet of the RFC 7766 §5 truncation
// counters. The counters alone are unreadable from a running daemon: the
// per-event warning is rate-limited to one line per minute, so it cannot say
// whether upgrades happen or how often they fail. The janitor summary is the
// answering mechanism, and it has to stay silent while nothing is happening.

// truncationSummaryLogger returns a logger writing parseable lines into buf.
func truncationSummaryLogger(buf *bytes.Buffer) *logrus.Logger {
	log := logrus.New()
	log.SetOutput(buf)
	log.SetLevel(logrus.InfoLevel)
	log.SetFormatter(&logrus.TextFormatter{DisableColors: true, DisableTimestamp: true})
	return log
}

func TestDnsTruncationSummaryIsSilentUntilSomethingHappens(t *testing.T) {
	ctrl := newCorpusDnsController(t, truncatedTestConfig())
	var buf bytes.Buffer
	ctrl.log = truncationSummaryLogger(&buf)

	ctrl.reportDnsTruncationSummary()
	if buf.Len() != 0 {
		t.Fatalf("an idle interval must not log, got %q", buf.String())
	}
}

func TestDnsTruncationSummaryReportsIntervalRateAndWarnsOnFailure(t *testing.T) {
	ctrl := newCorpusDnsController(t, truncatedTestConfig())
	var buf bytes.Buffer
	ctrl.log = truncationSummaryLogger(&buf)

	// One interval with two successful upgrades and one failure: the summary
	// must report the interval delta, the exact failure ratio and the lifetime
	// totals, at warn level because a client-visible truncated answer occurred.
	ctrl.dnsUdpTruncatedUpgrades.Add(2)
	ctrl.dnsUdpTruncatedUpgradeFailures.Add(1)
	ctrl.dnsTruncatedRepliesToClient.Add(1)
	ctrl.reportDnsTruncationSummary()

	first := buf.String()
	for _, want := range []string{
		"level=warning",
		"upgrades=2",
		"upgrade_failures=1",
		"truncated_replies=1",
		"upgrades_total=2",
		"upgrade_failures_total=1",
		"upgrade_failure_ratio=1/3",
	} {
		if !strings.Contains(first, want) {
			t.Fatalf("summary %q does not contain %q", first, want)
		}
	}
	buf.Reset()

	// The same interval reported again is empty: the deltas are consumed by the
	// report instead of being repeated on every tick.
	ctrl.reportDnsTruncationSummary()
	if buf.Len() != 0 {
		t.Fatalf("a repeated report must not repeat the previous interval, got %q", buf.String())
	}

	// A later interval with only successful upgrades is informational, and its
	// ratio is 0/1 rather than a lifetime average.
	ctrl.dnsUdpTruncatedUpgrades.Add(1)
	ctrl.reportDnsTruncationSummary()
	second := buf.String()
	if !strings.Contains(second, "level=info") {
		t.Fatalf("a successful interval must not warn, got %q", second)
	}
	for _, want := range []string{"upgrades=1", "upgrade_failures=0", "upgrade_failure_ratio=0/1", "upgrades_total=3"} {
		if !strings.Contains(second, want) {
			t.Fatalf("summary %q does not contain %q", second, want)
		}
	}
}
