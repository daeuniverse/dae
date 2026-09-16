/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// These tests pin the operational contract of the datapath counter report. The
// health check compared the counters against their lifetime totals, and
// bpf_stats_map is a handle every generation shares, so those totals never
// return to zero: one overflow ever observed produced a warning every 30s for
// the life of the process, and a lifetime total over the pressure threshold
// produced a CRITICAL error line the same way. The report has to describe the
// interval instead, stay silent while nothing moves, and keep every counter that
// has no per-event warning visible.

// overflowReportLogger returns a logger writing parseable lines into buf. It
// runs at debug level so the hot-path counters can be asserted too.
func overflowReportLogger(buf *bytes.Buffer) *logrus.Logger {
	log := logrus.New()
	log.SetOutput(buf)
	log.SetLevel(logrus.DebugLevel)
	log.SetFormatter(&logrus.TextFormatter{DisableColors: true, DisableTimestamp: true})
	return log
}

// primedOverflowReportPlane returns a plane whose report has adopted the given
// counters the way the first health tick of a running process does.
func primedOverflowReportPlane(t *testing.T, buf *bytes.Buffer, base time.Time) *ControlPlane {
	t.Helper()
	plane := &ControlPlane{}
	plane.log = overflowReportLogger(buf)
	plane.reportDatapathOverflowInterval(base, bpfStatsSnapshot{}, 0, 0, 4096)
	if buf.Len() != 0 {
		t.Fatalf("the priming tick must not log, got %q", buf.String())
	}
	return plane
}

func TestDatapathOverflowReportPrimesWithoutPublishingHistoricTotals(t *testing.T) {
	plane := &ControlPlane{}
	var buf bytes.Buffer
	plane.log = overflowReportLogger(&buf)

	// A fresh control plane adopts a bpf_stats_map that has been counting since
	// the first generation. Those totals are not an interval this process
	// measured, so the first tick may only adopt them as baselines.
	plane.reportDatapathOverflowInterval(time.Unix(1_700_000_000, 0), bpfStatsSnapshot{
		EventDrop:          5000,
		ParseUnsupportedL4: 900,
	}, 700, 0, 4096)

	if buf.Len() != 0 {
		t.Fatalf("the first observation must only establish baselines, got %q", buf.String())
	}
}

func TestDatapathOverflowReportStopsReportingAConditionThatStopped(t *testing.T) {
	var buf bytes.Buffer
	base := time.Unix(1_700_000_000, 0)
	plane := primedOverflowReportPlane(t, &buf, base)

	plane.reportDatapathOverflowInterval(base.Add(time.Minute), bpfStatsSnapshot{}, 12, 0, 4096)
	first := buf.String()
	for _, want := range []string{"level=warning", "udp_conn_overflow=12", "udp_conn_overflow_total=12"} {
		if !strings.Contains(first, want) {
			t.Fatalf("interval report %q does not contain %q", first, want)
		}
	}
	buf.Reset()

	// The counters stand still from here on, which is what a recovered datapath
	// looks like. The totals stay non-zero for the life of the process, so this
	// is exactly the case that used to re-alert every cooldown expiry.
	for tick := 2; tick <= 12; tick++ {
		plane.reportDatapathOverflowInterval(base.Add(time.Duration(tick)*time.Minute), bpfStatsSnapshot{}, 12, 0, 4096)
		if buf.Len() != 0 {
			t.Fatalf("tick %d re-reported a condition that stopped: %q", tick, buf.String())
		}
	}
}

func TestDatapathOverflowReportGradesTheInterval(t *testing.T) {
	var buf bytes.Buffer
	base := time.Unix(1_700_000_000, 0)
	plane := primedOverflowReportPlane(t, &buf, base)

	// Resource exhaustion in the interval is a warning that carries the
	// magnitude of the interval and the lifetime total next to it.
	plane.reportDatapathOverflowInterval(base.Add(time.Minute), bpfStatsSnapshot{RedirectOverflow: 40}, 0, 0, 8192)
	line := buf.String()
	for _, want := range []string{
		"level=warning",
		"redirect_overflow=40",
		"redirect_overflow_total=40",
		"conn_state_map_capacity=8192",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("interval report %q does not contain %q", line, want)
		}
	}
	buf.Reset()

	// A conn-state map that rejects this many flows in one interval is not
	// merely full, and the level has to say so.
	plane.reportDatapathOverflowInterval(base.Add(2*time.Minute), bpfStatsSnapshot{}, 0, datapathHeavyOverflowDelta+1, 8192)
	line = buf.String()
	for _, want := range []string{
		"level=error",
		"CRITICAL",
		"tcp_conn_overflow=101",
		"tcp_conn_overflow_total=101",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("heavy pressure report %q does not contain %q", line, want)
		}
	}
	buf.Reset()

	// The heavy interval is consumed, so the next quiet tick is silent even
	// though both lifetime totals still exceed the threshold.
	plane.reportDatapathOverflowInterval(base.Add(3*time.Minute), bpfStatsSnapshot{}, 0, datapathHeavyOverflowDelta+1, 8192)
	if buf.Len() != 0 {
		t.Fatalf("a consumed heavy interval must not re-alert, got %q", buf.String())
	}
}

func TestDatapathOverflowReportKeepsHotPathCountersAtDebug(t *testing.T) {
	var buf bytes.Buffer
	base := time.Unix(1_700_000_000, 0)
	plane := primedOverflowReportPlane(t, &buf, base)

	// Counters that describe by-design or already-warned states must reach the
	// operator under --debug instead of being read and thrown away, and they
	// must not raise a production line on their own.
	plane.reportDatapathOverflowInterval(base.Add(time.Minute), bpfStatsSnapshot{
		ParseUnsupportedL4: 40,
		UnsolicitedUDPSeen: 2,
		SockmarkFallback:   7,
		SynRebindRejected:  3,
	}, 0, 0, 0)

	line := buf.String()
	for _, want := range []string{
		"level=debug",
		"parse_unsupported_l4=40",
		"parse_unsupported_l4_total=40",
		"unsolicited_udp_seen=2",
		"sockmark_fallback=7",
		"syn_rebind_rejected=3",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("debug report %q does not contain %q", line, want)
		}
	}
	if strings.Contains(line, "level=warning") || strings.Contains(line, "level=error") {
		t.Fatalf("hot-path counters must not raise the level: %q", line)
	}
}

func TestDatapathOverflowReportPacesWithoutDroppingTheInterval(t *testing.T) {
	var buf bytes.Buffer
	base := time.Unix(1_700_000_000, 0)
	plane := primedOverflowReportPlane(t, &buf, base)

	// Inside the pacing window the line is withheld, but the activity is not
	// dropped: the next emitted line carries everything since the last one.
	plane.reportDatapathOverflowInterval(base.Add(5*time.Second), bpfStatsSnapshot{}, 3, 0, 0)
	plane.reportDatapathOverflowInterval(base.Add(20*time.Second), bpfStatsSnapshot{}, 5, 0, 0)
	if buf.Len() != 0 {
		t.Fatalf("a paced interval must not log, got %q", buf.String())
	}

	plane.reportDatapathOverflowInterval(base.Add(datapathOverflowReportInterval+time.Second), bpfStatsSnapshot{}, 5, 0, 0)
	line := buf.String()
	for _, want := range []string{"udp_conn_overflow=5", "udp_conn_overflow_total=5"} {
		if !strings.Contains(line, want) {
			t.Fatalf("paced report %q does not contain %q", line, want)
		}
	}
}

func TestDatapathOverflowReportRebaselinesAfterTheCounterRestarts(t *testing.T) {
	var buf bytes.Buffer
	base := time.Unix(1_700_000_000, 0)
	plane := primedOverflowReportPlane(t, &buf, base)

	plane.reportDatapathOverflowInterval(base.Add(time.Minute), bpfStatsSnapshot{EventDrop: 900}, 0, 0, 0)
	if !strings.Contains(buf.String(), "event_drop=900") {
		t.Fatalf("interval report %q does not carry the interval delta", buf.String())
	}
	buf.Reset()

	// The map behind the counters was replaced, so they restart at zero. That is
	// not a negative interval and must not wrap into an enormous delta.
	plane.reportDatapathOverflowInterval(base.Add(2*time.Minute), bpfStatsSnapshot{}, 0, 0, 0)
	if buf.Len() != 0 {
		t.Fatalf("a restarted counter must re-baseline silently, got %q", buf.String())
	}

	// The next interval is measured from the new baseline.
	plane.reportDatapathOverflowInterval(base.Add(3*time.Minute), bpfStatsSnapshot{EventDrop: 4}, 0, 0, 0)
	if !strings.Contains(buf.String(), "event_drop=4") {
		t.Fatalf("report after the restart %q is not measured from the new baseline", buf.String())
	}
}

func TestCheckBpfMapHealthReachesTheDatapathReportWithoutCounters(t *testing.T) {
	// The wiring as seen from the real entry point, not the arithmetic: the
	// health check must reach the report even when no map is loaded (the code
	// it replaced returned early in that case), must not panic on nil map
	// handles, and must stay silent because no counter moved.
	plane := &ControlPlane{core: &controlPlaneCore{}}
	var buf bytes.Buffer
	plane.log = overflowReportLogger(&buf)
	plane.core.bpf.Store(&bpfObjects{})

	plane.checkBpfMapHealth(0, 0)
	if buf.Len() != 0 {
		t.Fatalf("a datapath without counters must not log, got %q", buf.String())
	}
	if !plane.datapathOverflowReport.primed.Load() {
		t.Fatal("checkBpfMapHealth did not reach reportDatapathOverflowInterval: the baselines were never established")
	}
	if plane.datapathOverflowReport.lastReportTime.Load() == 0 {
		t.Fatal("checkBpfMapHealth did not reach the priming branch of the report")
	}

	// Repeated empty ticks stay silent and keep the baselines established.
	plane.checkBpfMapHealth(0, 0)
	if buf.Len() != 0 {
		t.Fatalf("repeated empty ticks must not log, got %q", buf.String())
	}
}

func TestClassifyDatapathOverflowIntervalGradesTheInterval(t *testing.T) {
	// The classifier is the whole grading contract, so it is tested on its own:
	// logrus orders levels most severe first, and a heavy interval must not be
	// masked by a lower-severity counter that also moved.
	template := []datapathOverflowField{
		{name: "udp_conn_overflow", level: logrus.WarnLevel, heavyDelta: datapathHeavyOverflowDelta},
		{name: "parse_unsupported_l4", level: logrus.DebugLevel},
	}
	for _, tc := range []struct {
		name      string
		deltas    []uint64
		wantLevel logrus.Level
		wantMoved bool
	}{
		{name: "idle interval", deltas: []uint64{0, 0}, wantLevel: logrus.DebugLevel, wantMoved: false},
		{name: "hot-path detail only", deltas: []uint64{0, 7}, wantLevel: logrus.DebugLevel, wantMoved: true},
		{name: "resource exhaustion", deltas: []uint64{1, 0}, wantLevel: logrus.WarnLevel, wantMoved: true},
		{name: "heavy pressure", deltas: []uint64{datapathHeavyOverflowDelta + 1, 0}, wantLevel: logrus.ErrorLevel, wantMoved: true},
		{name: "heavy pressure with hot-path detail", deltas: []uint64{datapathHeavyOverflowDelta + 1, 7}, wantLevel: logrus.ErrorLevel, wantMoved: true},
		{name: "threshold itself stays a warning", deltas: []uint64{datapathHeavyOverflowDelta, 0}, wantLevel: logrus.WarnLevel, wantMoved: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields := make([]datapathOverflowField, len(template))
			copy(fields, template)
			for i := range fields {
				fields[i].delta = tc.deltas[i]
			}
			level, moved := classifyDatapathOverflowInterval(fields)
			if level != tc.wantLevel || moved != tc.wantMoved {
				t.Fatalf("classifyDatapathOverflowInterval(%v) = (%v, %v), want (%v, %v)",
					tc.deltas, level, moved, tc.wantLevel, tc.wantMoved)
			}
		})
	}
}

func TestDatapathOverflowReportCoversEveryCounterWithoutAnotherOutlet(t *testing.T) {
	// Every bpf_stats_map counter this report owns must have exactly one row, so
	// that a counter cannot be read into the snapshot and then dropped: the
	// kernel-side comment promises these counters make a degradation visible.
	state := &controlPlaneDatapathOverflowReport{}
	fields := state.datapathOverflowFields(bpfStatsSnapshot{}, 0, 0)

	want := []string{
		"udp_conn_overflow",
		"tcp_conn_overflow",
		"redirect_overflow",
		"redirect_update_failed",
		"event_drop",
		"redirect_rebind_rejected",
		"syn_rebind_rejected",
		"rebind_rerouted_after_epoch_change",
		"parse_unsupported_l4",
		"unsolicited_udp_seen",
		"sockmark_fallback",
	}
	if len(fields) != len(want) {
		t.Fatalf("report covers %d counters, want %d: %v", len(fields), len(want), fieldNames(fields))
	}
	for i, name := range want {
		if fields[i].name != name {
			t.Fatalf("counter %d is %q, want %q (all: %v)", i, fields[i].name, name, fieldNames(fields))
		}
	}
	for _, name := range fieldNames(fields) {
		// The two by-design passthrough counters are published by
		// reportDatapathPassthroughSummary on the same tick; reporting them here
		// too would duplicate the line.
		if name == "stateless_tcp_passthrough" || name == "frag_tail_passed" {
			t.Fatalf("counter %q is owned by the passthrough summary and must not be reported twice", name)
		}
	}
}

// fieldNames returns the bracketed field names of a report for messages.
func fieldNames(fields []datapathOverflowField) []string {
	names := make([]string, 0, len(fields))
	for _, f := range fields {
		names = append(names, "["+f.name+"]")
	}
	return names
}
