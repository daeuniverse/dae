/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/dns"
	"github.com/sirupsen/logrus"
)

// These tests pin the level contract of RFC 7766 §5 truncation reporting: a
// truncated UDP answer that the TCP retry upgrades is normal operation (the
// client gets the complete answer), so it belongs at debug; only a failed
// upgrade, which really does hand the client a truncated answer, stays a
// warning. The upgrade counters and the janitor's interval summary keep the
// upgrade rate visible for an operator who never enables debug.

func newTruncationTestController(level logrus.Level) (*DnsController, *syncLogBuffer) {
	logger, out := newLogCapture(level)
	return &DnsController{
		dnsControllerStore: newDnsControllerStore(),
		log:                logger,
	}, out
}

func TestTruncationUpgradeIsNotAWarningAndIsStillCounted(t *testing.T) {
	c, out := newTruncationTestController(logrus.WarnLevel)
	upstream := &dns.Upstream{Scheme: "udp", Hostname: "8.8.8.8", Port: 53}

	c.reportDnsTruncatedFallback(upstream, true, nil, nil)

	if lines := out.lines(); len(lines) != 0 {
		t.Fatalf("a successful TCP upgrade must not warn, got %v", lines)
	}
	if got := c.dnsUdpTruncatedUpgrades.Load(); got != 1 {
		t.Fatalf("upgrade counter = %d, want 1: the event must stay counted when it is no longer warned", got)
	}
}

func TestTruncationUpgradeKeepsPerQueryDetailAtDebug(t *testing.T) {
	c, out := newTruncationTestController(logrus.DebugLevel)
	upstream := &dns.Upstream{Scheme: "udp", Hostname: "8.8.8.8", Port: 53}

	c.reportDnsTruncatedFallback(upstream, true, nil, nil)

	lines := out.lines()
	if len(lines) != 1 {
		t.Fatalf("debug lines = %d, want 1: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "level=debug") || !strings.Contains(lines[0], "truncated") {
		t.Fatalf("line %q is not the debug truncation detail", lines[0])
	}
}

func TestFailedTruncationUpgradeStaysAWarning(t *testing.T) {
	c, out := newTruncationTestController(logrus.InfoLevel)
	upstream := &dns.Upstream{Scheme: "udp", Hostname: "8.8.8.8", Port: 53}
	primaryErr := stderrors.New("udp answer truncated")
	fallbackErr := stderrors.New("tcp connect refused")

	c.reportDnsTruncatedFallback(upstream, false, primaryErr, fallbackErr)

	lines := out.lines()
	if len(lines) != 1 {
		t.Fatalf("warning lines = %d, want 1: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "level=warning") {
		t.Fatalf("line %q is not a warning: clients received a truncated answer", lines[0])
	}
	if got := c.dnsUdpTruncatedUpgradeFailures.Load(); got != 1 {
		t.Fatalf("upgrade failure counter = %d, want 1", got)
	}
}
