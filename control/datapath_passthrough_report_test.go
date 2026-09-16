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

// These tests pin the operational outlet of the two by-design passthrough
// counters (stateless established TCP, forwarded fragment tails). Both used to
// reach the operator as a per-event warning that the kernel emitted at most
// once per second for the whole datapath: a steady state therefore produced one
// WARN per second for as long as it lasted, and said nothing about how much
// traffic was affected. The janitor summary is the replacement, so it has to
// carry the magnitude, stay silent while nothing moves, and stay silent between
// its paced lines without losing the packets that arrived in between.

// passthroughReportLogger returns a logger writing parseable lines into buf.
// The level is Debug: the summary is a by-design steady-state report and logs
// at debug level, so the assertions below must observe debug output.
func passthroughReportLogger(buf *bytes.Buffer) *logrus.Logger {
	log := logrus.New()
	log.SetOutput(buf)
	log.SetLevel(logrus.DebugLevel)
	log.SetFormatter(&logrus.TextFormatter{DisableColors: true, DisableTimestamp: true})
	return log
}

// primePassthroughReport adopts the counters the way a daemon start does, so a
// test's first measured interval is a real one rather than the adoption tick.
func primePassthroughReport(plane *ControlPlane, now time.Time, snap bpfStatsSnapshot) {
	plane.reportDatapathPassthroughSummary(now, snap)
}

func TestDatapathPassthroughReportIsSilentUntilSomethingHappens(t *testing.T) {
	plane := &ControlPlane{}
	var buf bytes.Buffer
	plane.log = passthroughReportLogger(&buf)

	// The first observation adopts the counters: bpf_stats_map is shared across
	// generations, so whatever it holds at start is not this interval's
	// passthrough and must not be presented as one.
	base := time.Unix(1_700_000_000, 0)
	primePassthroughReport(plane, base, bpfStatsSnapshot{StatelessTCPPassthrough: 500_000})
	if buf.Len() != 0 {
		t.Fatalf("the adoption tick must not log, got %q", buf.String())
	}

	// An interval in which neither counter moved must not produce a line: the
	// whole point of the change is that the normal steady state is quiet.
	plane.reportDatapathPassthroughSummary(base.Add(datapathPassthroughReportInterval), bpfStatsSnapshot{StatelessTCPPassthrough: 500_000})
	if buf.Len() != 0 {
		t.Fatalf("an idle interval must not log, got %q", buf.String())
	}

	// And it stays quiet on every following idle tick.
	plane.reportDatapathPassthroughSummary(base.Add(2*datapathPassthroughReportInterval), bpfStatsSnapshot{StatelessTCPPassthrough: 500_000})
	if buf.Len() != 0 {
		t.Fatalf("repeated idle intervals must not log, got %q", buf.String())
	}
}

// TestCheckBpfMapHealthReachesThePassthroughReport pins the wiring from the
// real entry point, the way the sibling report pins its own: the arithmetic
// tests above call the report directly, so only an observable side effect of
// the adoption tick proves that checkBpfMapHealth still reaches it (the code
// it replaced returned early when the conn-state map was absent).
func TestCheckBpfMapHealthReachesThePassthroughReport(t *testing.T) {
	plane := &ControlPlane{core: &controlPlaneCore{}}
	var buf bytes.Buffer
	plane.log = passthroughReportLogger(&buf)
	plane.core.bpf.Store(&bpfObjects{})

	plane.checkBpfMapHealth(0, 0)
	if buf.Len() != 0 {
		t.Fatalf("a datapath without counters must not log, got %q", buf.String())
	}
	if !plane.datapathPassthroughReport.primed.Load() {
		t.Fatal("checkBpfMapHealth did not reach reportDatapathPassthroughSummary: the baselines were never established")
	}
	if plane.datapathPassthroughReport.lastReportTime.Load() == 0 {
		t.Fatal("checkBpfMapHealth did not reach the priming branch of the passthrough report")
	}
}

func TestDatapathPassthroughReportCarriesTheIntervalMagnitude(t *testing.T) {
	plane := &ControlPlane{}
	var buf bytes.Buffer
	plane.log = passthroughReportLogger(&buf)

	base := time.Unix(1_700_000_000, 0)
	primePassthroughReport(plane, base, bpfStatsSnapshot{})

	// T0+60s: the first measured interval is one interval after the adoption
	// tick, so it is emitted and reports its own delta.
	plane.reportDatapathPassthroughSummary(base.Add(datapathPassthroughReportInterval), bpfStatsSnapshot{
		StatelessTCPPassthrough: 1000,
	})
	first := buf.String()
	for _, want := range []string{
		"level=debug",
		"stateless_tcp_passthrough=1000",
		"frag_tail_passed=0",
		"stateless_tcp_passthrough_total=1000",
		"frag_tail_passed_total=0",
	} {
		if !strings.Contains(first, want) {
			t.Fatalf("report %q does not contain %q", first, want)
		}
	}
	buf.Reset()

	// The interval is consumed by the line: an unchanged snapshot on the next
	// tick is back to silence, because those packets were already shown.
	plane.reportDatapathPassthroughSummary(base.Add(datapathPassthroughReportInterval+5*time.Second), bpfStatsSnapshot{
		StatelessTCPPassthrough: 1000,
	})
	if buf.Len() != 0 {
		t.Fatalf("a consumed interval must not log again, got %q", buf.String())
	}

	// Inside the pacing window the line is withheld, but the packets are not
	// dropped: the next line carries everything since the last one.
	plane.reportDatapathPassthroughSummary(base.Add(datapathPassthroughReportInterval+30*time.Second), bpfStatsSnapshot{
		StatelessTCPPassthrough: 1100,
	})
	if buf.Len() != 0 {
		t.Fatalf("a paced interval must not log, got %q", buf.String())
	}
	plane.reportDatapathPassthroughSummary(base.Add(2*datapathPassthroughReportInterval), bpfStatsSnapshot{
		StatelessTCPPassthrough: 1200,
		FragTailPassed:          1,
	})
	second := buf.String()
	for _, want := range []string{
		// 1200 - 1000: the 100 packets of the withheld tick and the 100 of
		// this one are both in the line, so pacing delays the magnitude
		// without losing any of it.
		"stateless_tcp_passthrough=200",
		"frag_tail_passed=1",
		"stateless_tcp_passthrough_total=1200",
		"frag_tail_passed_total=1",
	} {
		if !strings.Contains(second, want) {
			t.Fatalf("report %q does not contain %q", second, want)
		}
	}
	buf.Reset()

	// A condition that stops moving stops being reported, which is what keeps
	// a datapath that never recovers from flooding the log forever.
	plane.reportDatapathPassthroughSummary(base.Add(3*datapathPassthroughReportInterval), bpfStatsSnapshot{
		StatelessTCPPassthrough: 1200,
		FragTailPassed:          1,
	})
	if buf.Len() != 0 {
		t.Fatalf("a stopped counter must not log, got %q", buf.String())
	}
}

// TestDatapathPassthroughReportSurvivesACounterReset pins the one way these
// counters move backwards: a datapath reload replaces bpf_stats_map with a
// fresh one, and a reload window can leave no readable map at all. The interval
// is then not measurable, so it must be adopted silently rather than reported
// as a wrapped 20-digit number, and the counters must keep working after it.
func TestDatapathPassthroughReportSurvivesACounterReset(t *testing.T) {
	plane := &ControlPlane{}
	var buf bytes.Buffer
	plane.log = passthroughReportLogger(&buf)

	base := time.Unix(1_700_000_000, 0)
	primePassthroughReport(plane, base, bpfStatsSnapshot{})
	plane.reportDatapathPassthroughSummary(base.Add(datapathPassthroughReportInterval), bpfStatsSnapshot{StatelessTCPPassthrough: 9000})
	if !strings.Contains(buf.String(), "stateless_tcp_passthrough=9000") {
		t.Fatalf("first report %q does not contain the interval count", buf.String())
	}
	buf.Reset()

	// The reload: the fresh map reports a total below the previous baseline.
	plane.reportDatapathPassthroughSummary(base.Add(2*datapathPassthroughReportInterval), bpfStatsSnapshot{StatelessTCPPassthrough: 12})
	if buf.Len() != 0 {
		t.Fatalf("a reset interval must be adopted silently, got %q", buf.String())
	}

	// The new map keeps counting, and the next interval is measured from the
	// adopted baseline rather than from the old one.
	plane.reportDatapathPassthroughSummary(base.Add(3*datapathPassthroughReportInterval), bpfStatsSnapshot{StatelessTCPPassthrough: 25})
	line := buf.String()
	if !strings.Contains(line, "stateless_tcp_passthrough=13") {
		t.Fatalf("post-reset report %q does not measure from the adopted baseline", line)
	}
	if strings.Contains(line, "1844674407370955") {
		t.Fatalf("post-reset report %q carries an underflowed interval", line)
	}
}
