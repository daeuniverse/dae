/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

// TestRejectedDomainsWarnOnceThenAggregate is the Q5 contract. An invalid
// domain pattern used to produce one warning per entry, so a subscription that
// carried hundreds of them produced hundreds of warnings; a pattern that is
// rejected never enters the trie, so it does not participate in routing at all
// and the number of dropped entries is a correctness fact an operator has to
// see. The first rejection is a warning with its offending character, later
// ones are debug detail, and one aggregate line closes the rule with the count.
func TestRejectedDomainsWarnOnceThenAggregate(t *testing.T) {
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.WarnLevel)

	matcher := NewAhocorasickSlimtrie(logger, 32)
	matcher.AddSet(0, []string{
		"good.example.com",
		"bad*domain.example.com",
		"worse?domain.example.com",
		"also/bad.example.com",
	}, consts.RoutingDomainKey_Full)

	entries := hook.AllEntries()
	if len(entries) != 2 {
		t.Fatalf("AddSet emitted %d warning(s), want 2 (first rejection + one aggregate)", len(entries))
	}

	first := entries[0]
	if first.Level != logrus.WarnLevel || !strings.Contains(first.Message, "bad full domain rejected") {
		t.Fatalf("first warning = %v %q, want the concrete first rejection", first.Level, first.Message)
	}
	if got := first.Data["domain"]; got != "bad*domain.example.com" {
		t.Fatalf("first warning domain = %v, want the first rejected pattern", got)
	}
	if got := first.Data["char"]; got != "*" {
		t.Fatalf("first warning char = %v, want \"*\"", got)
	}

	summary := entries[1]
	if summary.Level != logrus.WarnLevel {
		t.Fatalf("aggregate rejection line level = %v, want warn", summary.Level)
	}
	if got := summary.Data["skipped"]; got != uint64(3) {
		t.Fatalf("aggregate line skipped=%v, want 3 (every dropped pattern must be counted)", got)
	}
	if got := summary.Data["rule_index"]; got != 0 {
		t.Fatalf("aggregate line rule_index=%v, want 0", got)
	}
	if !strings.Contains(summary.Message, "NOT used for routing") {
		t.Fatalf("aggregate message %q does not say the patterns do not participate in routing", summary.Message)
	}
	if got := matcher.SkippedDomainCount(); got != 3 {
		t.Fatalf("SkippedDomainCount() = %d, want 3", got)
	}

	// The dropped patterns really are absent: only the good one routes.
	if err := matcher.Build(); err != nil {
		t.Fatal(err)
	}
	if bitmap := matcher.MatchDomainBitmap("good.example.com"); bitmap[0]&1 == 0 {
		t.Fatal("the valid pattern did not match after the rejected ones were skipped")
	}
	for _, dropped := range []string{"bad*domain.example.com", "worse?domain.example.com", "also/bad.example.com"} {
		if bitmap := matcher.MatchDomainBitmap(dropped); bitmap[0]&1 != 0 {
			t.Fatalf("rejected pattern %q matched rule bit 0; it must not participate in routing", dropped)
		}
	}
}

// TestRejectedDomainDetailStaysAvailableAtDebug checks the other half: the
// aggregate keeps the count, and each dropped entry keeps its own cause at
// debug so a mixed batch stays diagnosable.
func TestRejectedDomainDetailStaysAvailableAtDebug(t *testing.T) {
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)

	matcher := NewAhocorasickSlimtrie(logger, 32)
	matcher.AddSet(3, []string{"a*b", "c*d"}, consts.RoutingDomainKey_Suffix)

	detailed := 0
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.DebugLevel && strings.Contains(entry.Message, "bad suffix domain rejected") {
			detailed++
		}
	}
	if detailed != 1 {
		t.Fatalf("per-entry rejection detail at debug = %d line(s), want 1 (the entries after the first)", detailed)
	}
}

// TestNoRejectedDomainsMeansNoWarning keeps the aggregate line honest: a clean
// rule must not produce a "0 patterns rejected" warning.
func TestNoRejectedDomainsMeansNoWarning(t *testing.T) {
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.WarnLevel)

	matcher := NewAhocorasickSlimtrie(logger, 32)
	matcher.AddSet(0, []string{"good.example.com", "www.good.example.com"}, consts.RoutingDomainKey_Full)
	if got := len(hook.AllEntries()); got != 0 {
		t.Fatalf("a rule with no rejected pattern emitted %d warning(s), want 0", got)
	}
	if got := matcher.SkippedDomainCount(); got != 0 {
		t.Fatalf("SkippedDomainCount() = %d, want 0", got)
	}
}
