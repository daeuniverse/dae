/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

// TestBindOutcomeLevelsFollowTheFirstBindOrFailureRule is the Q2 contract. The
// LAN/WAN new-link callbacks used to warn on every link appearance, so a
// container host that creates veth devices at runtime produced a warning per
// device for a normal event, while a real bind failure was one error line with
// no indication of how often it had failed. The rule now is:
//
//	first bind (success or failure) -> info, always visible
//	later success                   -> nothing (no datapath state changed)
//	later failure                   -> warn, with the consecutive count
//	success after failures          -> info, the failure state ended
//
// and two counters keep the volume of the folded-away successes visible.
func TestBindOutcomeLevelsFollowTheFirstBindOrFailureRule(t *testing.T) {
	core := &controlPlaneCore{}
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.InfoLevel)
	core.log = logger

	// First attempt, success: the milestone is info, not warn.
	core.logBindOutcome("eth0", true, nil)
	if got := len(hook.AllEntries()); got != 1 {
		t.Fatalf("first successful bind emitted %d entries, want 1 info line", got)
	}
	first := hook.LastEntry()
	if first.Level != logrus.InfoLevel {
		t.Fatalf("first successful bind level = %v, want info", first.Level)
	}
	if got := first.Data["first_bind"]; got != true {
		t.Fatalf("first bind line is missing first_bind=true (got %v)", got)
	}
	if got := core.bindAttemptCount(); got != 1 {
		t.Fatalf("bindAttemptCount() = %d, want 1", got)
	}

	// Later success on the same healthy link: routine, no new event.
	hook.Reset()
	core.logBindOutcome("eth0", true, nil)
	if got := len(hook.AllEntries()); got != 0 {
		t.Fatalf("routine re-bind emitted %d entries, want 0 (counted, not logged)", got)
	}
	if got := core.bindAttemptCount(); got != 2 {
		t.Fatalf("bindAttemptCount() = %d, want 2", got)
	}

	// First failure: still visible without being an error wall.
	hook.Reset()
	core.logBindOutcome("eth0", true, errors.New("no such device"))
	if got := len(hook.AllEntries()); got != 1 {
		t.Fatalf("first bind failure emitted %d entries, want 1", got)
	}
	if got := hook.LastEntry().Level; got != logrus.WarnLevel {
		t.Fatalf("first bind failure level = %v, want warn", got)
	}
	if got := core.bindFailureCount(); got != 1 {
		t.Fatalf("bindFailureCount() = %d, want 1", got)
	}

	// Consecutive failure: warn again with the running count.
	hook.Reset()
	core.logBindOutcome("eth0", true, errors.New("no such device"))
	last := hook.LastEntry()
	if last.Level != logrus.WarnLevel {
		t.Fatalf("second consecutive failure level = %v, want warn", last.Level)
	}
	if got := last.Data["consecutive_failures"]; got != uint64(2) {
		t.Fatalf("second consecutive failure reported consecutive_failures=%v, want 2", got)
	}

	// Recovery: the failure interval closes visibly.
	hook.Reset()
	core.logBindOutcome("eth0", true, nil)
	if got := hook.LastEntry().Level; got != logrus.InfoLevel {
		t.Fatalf("recovery level = %v, want info", got)
	}

	// A different interface has its own first bind, and the LAN/WAN scopes do
	// not share state: "eth0" bound as LAN says nothing about eth0 as WAN.
	hook.Reset()
	core.logBindOutcome("eth1", true, nil)
	core.logBindOutcome("eth0", false, nil)
	entries := hook.AllEntries()
	if len(entries) != 2 {
		t.Fatalf("new interface and new scope emitted %d entries, want 2 first-bind lines", len(entries))
	}
	for _, entry := range entries {
		if entry.Level != logrus.InfoLevel || entry.Data["first_bind"] != true {
			t.Fatalf("entry %v %q is not an info first-bind line", entry.Level, entry.Message)
		}
	}
}

// TestBindOutcomeAfterLinkReappearanceIsAFirstBindAgain pins the link
// lifecycle: the delete callbacks call forgetBindState, so the bind of a
// re-created interface is reported as a first bind (that is the milestone the
// lazy-bind callback exists for), not folded into the previous link's routine
// re-binds. The previous link's failure count must not leak into it either.
func TestBindOutcomeAfterLinkReappearanceIsAFirstBindAgain(t *testing.T) {
	core := &controlPlaneCore{}
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.InfoLevel)
	core.log = logger

	// A link that appeared once and whose bind then failed twice.
	core.logBindOutcome("eth0", true, nil)
	core.logBindOutcome("eth0", true, errors.New("no such device"))
	core.logBindOutcome("eth0", true, errors.New("no such device"))

	// The link goes away: the delete callback forgets its outcome.
	core.forgetBindState("eth0")

	hook.Reset()
	core.logBindOutcome("eth0", true, errors.New("no such device"))
	entry := hook.LastEntry()
	if entry.Level != logrus.InfoLevel {
		t.Fatalf("first bind of the re-created link level = %v, want info", entry.Level)
	}
	if got := entry.Data["first_bind"]; got != true {
		t.Fatalf("first bind of the re-created link is missing first_bind=true (got %v)", got)
	}
	if got := entry.Data["attempt"]; got != uint64(1) {
		t.Fatalf("re-created link attempt = %v, want 1 (a new link starts over)", got)
	}
}

// TestBindOutcomeCoversBothDirections pins the fan-out: bindLan and bindWan
// each need both callbacks converted, otherwise one direction keeps warning on
// every link appearance.
func TestBindOutcomeCoversBothDirections(t *testing.T) {
	src := readPackageSource(t, "control_plane_core_bind.go")
	for _, gone := range []string{
		`c.log.Warnf("New link creation of '%v' is detected. Bind LAN program to it."`,
		`c.log.Warnf("New link creation of '%v' is detected. Bind WAN program to it."`,
		`c.log.Warnf("Link deletion of '%v' is detected. Bind LAN program to it once it is re-created."`,
		`c.log.Warnf("Link deletion of '%v' is detected. Bind WAN program to it once it is re-created."`,
		`c.log.Errorf("bindLan: %v", err)`,
		`c.log.Errorf("bindWan: %v", err)`,
	} {
		if strings.Contains(src, gone) {
			t.Fatalf("link-event callback still reports at warn/error: %s", gone)
		}
	}
	for _, want := range []string{
		`c.log.Infof("New link creation of '%v' is detected. Bind LAN program to it."`,
		`c.log.Infof("New link creation of '%v' is detected. Bind WAN program to it."`,
		`c.log.Infof("Link deletion of '%v' is detected. Bind LAN program to it once it is re-created."`,
		`c.log.Infof("Link deletion of '%v' is detected. Bind WAN program to it once it is re-created."`,
		`c.logBindOutcome(link.Attrs().Name, true, attach(link))`,
		`c.logBindOutcome(link.Attrs().Name, false, attach(link))`,
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("link-event callback is missing %s", want)
		}
	}
	// The failure must still be reported: dropping the callback's own report
	// is only allowed because logBindOutcome warns.
	if !strings.Contains(src, "logBindOutcome") {
		t.Fatal("bind outcomes are no longer reported at all")
	}
}
