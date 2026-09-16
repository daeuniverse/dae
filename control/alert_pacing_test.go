/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	stderrors "errors"
)

// These tests pin the log pacing contract: a condition that stays true across
// many maintenance ticks, packets or queries is reported once per pace with the
// number of observations it has accumulated, so the repeats stay visible as a
// magnitude instead of becoming one line per tick (which buries the transition
// lines) or disappearing entirely (which hides that the condition never
// cleared).

// syncLogBuffer collects log output from goroutines that log concurrently.
type syncLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncLogBuffer) lines() []string {
	var out []string
	for line := range strings.SplitSeq(b.String(), "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

// newLogCapture returns a logger at the given level that writes plain
// (uncoloured, untimestamped) lines into the returned buffer.
func newLogCapture(level logrus.Level) (*logrus.Logger, *syncLogBuffer) {
	out := &syncLogBuffer{}
	logger := logrus.New()
	logger.SetOutput(out)
	logger.SetLevel(level)
	logger.SetFormatter(&logrus.TextFormatter{DisableColors: true, DisableTimestamp: true})
	return logger, out
}

func TestPacedAlertEmitsFirstObservationAndCountsRepeats(t *testing.T) {
	var alert pacedAlert
	base := time.Unix(1700000000, 0)

	observations, emit := alert.observe(base, time.Minute)
	if !emit {
		t.Fatal("the first observation must be emitted: a condition seen once is never a repeat")
	}
	if observations != 1 {
		t.Fatalf("first observation count = %d, want 1", observations)
	}

	for i := 2; i <= 5; i++ {
		observations, emit = alert.observe(base.Add(time.Duration(i)*time.Second), time.Minute)
		if emit {
			t.Fatalf("observation %d was emitted inside the cooldown", i)
		}
		if observations != uint64(i) {
			t.Fatalf("observation %d count = %d, want %d: suppressed observations must still be counted", i, observations, i)
		}
	}
}

func TestPacedAlertEmitsAgainAfterCooldownWithTheAccumulatedCount(t *testing.T) {
	var alert pacedAlert
	base := time.Unix(1700000000, 0)

	if _, emit := alert.observe(base, time.Minute); !emit {
		t.Fatal("the first observation must be emitted")
	}
	if _, emit := alert.observe(base.Add(59*time.Second), time.Minute); emit {
		t.Fatal("an observation inside the cooldown must not be emitted")
	}

	observations, emit := alert.observe(base.Add(60*time.Second), time.Minute)
	if !emit {
		t.Fatal("an observation at the end of the cooldown must be emitted")
	}
	if observations != 3 {
		t.Fatalf("count after the cooldown = %d, want 3: the emitted line carries the magnitude of everything it suppressed", observations)
	}
}

func TestPacedAlertsAreIndependent(t *testing.T) {
	var first, second pacedAlert
	base := time.Unix(1700000000, 0)

	if _, emit := first.observe(base, time.Minute); !emit {
		t.Fatal("first alert, first observation must be emitted")
	}
	if _, emit := second.observe(base, time.Minute); !emit {
		t.Fatal("one alert's pace must not suppress another alert: each condition needs its own line")
	}
}

// TestLogMapCapacityAlertPacesRepeatsAndCarriesTheCount exercises the real call
// path the three janitor maps use: a map that stays above its capacity
// threshold is revisited by the janitor every 1s..30s, and must not write one
// line per visit. The suppressed visits are not lost - they are counted, and
// the next emitted line reports them.
func TestLogMapCapacityAlertPacesRepeatsAndCarriesTheCount(t *testing.T) {
	logger, out := newLogCapture(logrus.WarnLevel)
	c := &ControlPlane{log: logger}

	for range 7 {
		c.logMapCapacityAlert(&c.redirectTrackCapacityAlert, "cleanupRedirectTrackMap", 93.5, 4096)
	}

	lines := out.lines()
	if len(lines) != 1 {
		t.Fatalf("7 above-threshold observations produced %d lines, want 1: %v", len(lines), lines)
	}
	line := lines[0]
	for _, want := range []string{"cleanupRedirectTrackMap", "93.5% capacity", "4096 entries"} {
		if !strings.Contains(line, want) {
			t.Fatalf("aggregated line %q is missing %q", line, want)
		}
	}
	if got := c.redirectTrackCapacityAlert.observations.Load(); got != 7 {
		t.Fatalf("observations = %d, want 7: the paced visits must still be counted", got)
	}

	// Let the pace elapse: the next visit reports the magnitude of everything
	// that was folded into the count instead of writing nothing at all.
	rewindPace(&c.redirectTrackCapacityAlert, time.Now(), mapCapacityAlertCooldown)
	c.logMapCapacityAlert(&c.redirectTrackCapacityAlert, "cleanupRedirectTrackMap", 94.0, 4100)
	lines = out.lines()
	if len(lines) != 2 {
		t.Fatalf("after the pace, lines = %d, want 2: %v", len(lines), lines)
	}
	if !strings.Contains(lines[1], "observed 8 times") {
		t.Fatalf("aggregated line %q does not carry the accumulated observation count", lines[1])
	}
}

// TestLogMapCapacityAlertKeepsEachMapIndependent pins that one saturated map
// cannot pace another map's alert out of the log.
func TestLogMapCapacityAlertKeepsEachMapIndependent(t *testing.T) {
	logger, out := newLogCapture(logrus.WarnLevel)
	c := &ControlPlane{log: logger}

	c.logMapCapacityAlert(&c.redirectTrackCapacityAlert, "cleanupRedirectTrackMap", 93.5, 4096)
	c.logMapCapacityAlert(&c.cookiePidCapacityAlert, "cleanupCookiePidMap", 91.0, 2048)
	c.logMapCapacityAlert(&c.routingHandoffCapacityAlert, "cleanupRoutingHandoffMap", 99.0, 1024)

	lines := out.lines()
	if len(lines) != 3 {
		t.Fatalf("three different maps produced %d lines, want 3: %v", len(lines), lines)
	}
	for _, name := range []string{"cleanupRedirectTrackMap", "cleanupCookiePidMap", "cleanupRoutingHandoffMap"} {
		found := false
		for _, line := range lines {
			if strings.Contains(line, name) {
				found = true
			}
		}
		if !found {
			t.Fatalf("no line for %s in %v", name, lines)
		}
	}
}

// TestUdpIngressFailuresArePacedPerCondition is the per-packet regression: one
// failing destination used to write one warning per packet of every flow to it.
// Each condition keeps its own pace, and the packets it covers stay counted.
func TestUdpIngressFailuresArePacedPerCondition(t *testing.T) {
	logger, out := newLogCapture(logrus.WarnLevel)
	c := &ControlPlane{log: logger}
	src := netip.MustParseAddrPort("10.0.0.2:44444")
	dst := netip.MustParseAddrPort("198.51.100.7:443")
	failure := stderrors.New("touch max retry limit")

	for range 5 {
		c.logUdpRoutingTupleFailure(failure)
		c.logUdpDNSRoutingTupleFailure(src, dst, failure)
		c.logUdpHandlePktFailure(failure)
	}

	lines := out.lines()
	if len(lines) != 3 {
		t.Fatalf("three per-packet conditions produced %d lines, want 3: %v", len(lines), lines)
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{
		"No AddrPort presented",
		"UDP routing tuple lookup failed for DNS",
		"handlePkt",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("paced output %q is missing %q", joined, want)
		}
	}
	for name, alert := range map[string]*pacedAlert{
		"routing tuple":     &c.udpRoutingTupleWarnAlert,
		"dns routing tuple": &c.udpDNSRoutingTupleWarnAlert,
		"handlePkt":         &c.udpHandlePktWarnAlert,
	} {
		if got := alert.observations.Load(); got != 5 {
			t.Fatalf("%s observations = %d, want 5: suppressed packets must still be counted", name, got)
		}
	}

	rewindPace(&c.udpHandlePktWarnAlert, time.Now(), udpIngressWarnLogInterval)
	c.logUdpHandlePktFailure(failure)
	lines = out.lines()
	if len(lines) != 4 {
		t.Fatalf("after the pace, lines = %d, want 4: %v", len(lines), lines)
	}
	if !strings.Contains(lines[3], "packets=6") {
		t.Fatalf("paced line %q does not carry the accumulated packet count", lines[3])
	}
}

// TestUdpIngressFailurePacingDoesNotHideALaterCondition documents the operator
// guarantee behind the pace: the count keeps growing while the condition lasts,
// so the absence of new lines never means "recovered" on its own.
func TestUdpIngressFailurePacingDoesNotHideALaterCondition(t *testing.T) {
	logger, out := newLogCapture(logrus.WarnLevel)
	c := &ControlPlane{log: logger}
	failure := stderrors.New("touch max retry limit")

	c.logUdpHandlePktFailure(failure)
	c.logUdpHandlePktFailure(failure)
	if lines := out.lines(); len(lines) != 1 {
		t.Fatalf("two observations produced %d lines, want 1: %v", len(lines), lines)
	}

	// The same alert keeps counting: a later emitted line reports both packets.
	rewindPace(&c.udpHandlePktWarnAlert, time.Now(), udpIngressWarnLogInterval)
	c.logUdpHandlePktFailure(failure)
	lines := out.lines()
	if len(lines) != 2 {
		t.Fatalf("lines after the pace = %d, want 2: %v", len(lines), lines)
	}
	if !strings.Contains(lines[1], "packets=3") {
		t.Fatalf("line %q does not report all three packets", lines[1])
	}
}

// rewindPace moves an alert's last-emitted timestamp far enough into the past
// that the next observation is emitted again. It lets a test observe the
// long-run behaviour of a paced alert without waiting for the pace to elapse,
// and it only touches the pace, never the accumulated count.
func rewindPace(alert *pacedAlert, now time.Time, cooldown time.Duration) {
	alert.lastEmitNano.Store(now.Add(-2 * cooldown).UnixNano())
}
