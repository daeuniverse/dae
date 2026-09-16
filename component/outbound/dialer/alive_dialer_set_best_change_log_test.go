/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

// TestBestDialerChangeLogsOneInfoLineAndTableAtDebug is the Q8 contract. A
// best-dialer change used to emit the milestone line and then the whole
// per-dialer latency table at info, so one event produced 1+N info lines and
// log_level=info read like a latency dump. The milestone now stands alone at
// info (with the reason and the key numbers) and the table moved to debug,
// where the ordering behind the decision stays available.
func TestBestDialerChangeLogsOneInfoLineAndTableAtDebug(t *testing.T) {
	networkType := newTestNetworkType()
	d1 := newNamedTestDialer(t, "q8-1")
	d2 := newNamedTestDialer(t, "q8-2")

	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.InfoLevel)
	d1.Log = logger
	d2.Log = logger

	set := NewAliveDialerSet(
		logger,
		"q8-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_MinLastLatency,
		[]*Dialer{d1, d2},
		[]*Annotation{{}, {}},
		func(bool) {},
		false,
	)
	d1.RegisterAliveDialerSet(set)
	d2.RegisterAliveDialerSet(set)
	t.Cleanup(func() {
		d1.UnregisterAliveDialerSet(set)
		d2.UnregisterAliveDialerSet(set)
	})

	// Both dialers are alive on an optimistic 0-latency key. A real probe
	// latency for d1 re-ranks the group onto d2, which is the path under test.
	appendLatencyLocked(d1, networkType, 100*time.Millisecond)

	hook.Reset()
	set.NotifyLatencyChange(d1, true)

	infoLines := 0
	debugTables := 0
	for _, entry := range hook.AllEntries() {
		switch entry.Level {
		case logrus.InfoLevel:
			infoLines++
		case logrus.DebugLevel:
			if strings.Contains(entry.Message, "Group 'q8-group'") {
				debugTables++
			}
		}
	}
	if infoLines != 1 {
		t.Fatalf("best-dialer change emitted %d info line(s), want exactly 1 (the milestone)", infoLines)
	}

	milestone := hook.LastEntry()
	if milestone == nil || !strings.Contains(milestone.Message, "selects dialer") {
		t.Fatalf("last info entry = %v, want the selection milestone", milestone)
	}
	if got := milestone.Data["reason"]; got != "best latency" {
		t.Fatalf("milestone reason = %v, want \"best latency\"", got)
	}
	if got := milestone.Data["_new_dialer"]; got != "q8-2" {
		t.Fatalf("milestone new dialer = %v, want q8-2", got)
	}
	if got, ok := milestone.Data["alive_dialers"]; !ok || got != 2 {
		t.Fatalf("milestone alive_dialers = %v (present=%v), want 2", got, ok)
	}

	// The table is not deleted, only demoted: debug must carry it.
	logger.SetLevel(logrus.DebugLevel)
	hook.Reset()
	// Force the next change: d2's real latency makes d1 (recorded at 100ms)
	// the best again. appendLatencyLocked keeps the collection lock discipline
	// the render depends on.
	appendLatencyLocked(d2, networkType, 500*time.Millisecond)
	set.NotifyLatencyChange(d2, true)

	debugTables = 0
	infoLines = 0
	for _, entry := range hook.AllEntries() {
		switch entry.Level {
		case logrus.InfoLevel:
			infoLines++
		case logrus.DebugLevel:
			if strings.Contains(entry.Message, "Group 'q8-group'") {
				debugTables++
			}
		}
	}
	if debugTables != 1 {
		t.Fatalf("latency table rendered %d time(s) at debug, want exactly 1", debugTables)
	}
	if infoLines != 1 {
		t.Fatalf("second best-dialer change emitted %d info line(s), want exactly 1", infoLines)
	}
}

// appendLatencyLocked gives a dialer a probe latency under its collection lock,
// which is the same discipline the health-check cycle uses.
func appendLatencyLocked(d *Dialer, networkType *NetworkType, latency time.Duration) {
	d.collectionFineMu.Lock()
	d.mustGetCollection(networkType).Latencies10.AppendLatency(latency)
	d.collectionFineMu.Unlock()
}

// TestLatencyTableIsNotRenderedAtInfoLevel pins the gate: the render walks
// every dialer, so it must not be built when debug is off.
func TestLatencyTableIsNotRenderedAtInfoLevel(t *testing.T) {
	networkType := newTestNetworkType()
	d1 := newNamedTestDialer(t, "q8-gate")
	logger, _ := test.NewNullLogger()
	logger.SetLevel(logrus.InfoLevel)
	d1.Log = logger

	set := NewAliveDialerSet(
		logger,
		"q8-gate-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_MinLastLatency,
		[]*Dialer{d1},
		[]*Annotation{{}},
		func(bool) {},
		false,
	)
	t.Cleanup(func() { d1.UnregisterAliveDialerSet(set) })

	if _, ok := set.snapshotLatenciesLocked(); ok {
		t.Fatal("latency snapshot was built at info level; the table is debug-only")
	}
	logger.SetLevel(logrus.DebugLevel)
	if _, ok := set.snapshotLatenciesLocked(); !ok {
		t.Fatal("latency snapshot was not built at debug level; the table would be lost")
	}
}
