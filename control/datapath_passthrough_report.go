/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// This file owns the operator-visible outlet of the two bpf_stats_map counters
// that describe a by-design passthrough: established TCP forwarded without a
// cached routing decision, and forwarded non-initial fragments. Both paths used
// to reach the operator as a per-event warning, which is the wrong shape for a
// steady state twice over:
//
//   - The kernel rate key of an event type is shared by every flow of that
//     type (send_anomaly_event passes EVENT_RATE.stateless_tcp_key for all of
//     them), so the ceiling was one WARN per second for the whole datapath, for
//     as long as the state lasted. Established TCP without cached state is what
//     every pre-existing flow does after a restart, so "as long as" is hours.
//   - The tuple in such a record is one arbitrary sample of the condition. It
//     cannot answer the only question an operator can act on: how much traffic
//     is bypassing routing. The per-packet counters can.
//
// The report therefore reads the counters the health tick already read, and
// follows the rules of the sibling report in control/datapath_overflow_report.go
// (which deliberately excludes these two counters to keep them from being
// reported twice): the line describes the interval since the previous line, it
// is emitted only in an interval that moved, and the baselines advance only when
// a line is emitted, so a paced interval is carried into the next line instead
// of being dropped. The pacing and the message differ from the sibling: these
// counters describe a normal steady state rather than resource exhaustion, so
// they are paced slower and always explained rather than graded by severity.
const (
	// datapathPassthroughReportInterval paces the line. The health tick runs
	// every 5s, which for a state that lasts as long as the flows it describes
	// would only trade one line per second for one line per 5s. The sibling
	// report uses 30s because its counters mean a resource is being exhausted;
	// a passthrough interval is normal, so it is reported half as often, which
	// caps a sustained condition at 60 lines/hour instead of 3600 while still
	// showing an operator a restart's effect within a minute and showing when
	// it ends.
	datapathPassthroughReportInterval = time.Minute
)

// controlPlaneDatapathPassthroughReport holds the counter values the last
// emitted line consumed. primed records that the baselines were established:
// bpf_stats_map is shared across generations, so the first observation must
// adopt what it finds instead of presenting a lifetime total as an interval.
type controlPlaneDatapathPassthroughReport struct {
	primed         atomic.Bool
	lastReportTime atomic.Int64

	statelessTCPPassthrough atomic.Uint64
	fragTailPassed          atomic.Uint64
}

// reportDatapathPassthroughSummary publishes one interval of the two
// by-design passthrough counters. It is called from the health tick with the
// snapshot that tick already read, so it costs no extra map read.
//
// The message states what happened and why it is expected, because the fields
// are the whole point: the interval deltas are the magnitude, and the running
// totals next to them show whether the condition is a restart-sized burst that
// is decaying or a flow that never got routed.
func (c *ControlPlane) reportDatapathPassthroughSummary(now time.Time, snap bpfStatsSnapshot) {
	if c == nil || c.log == nil {
		return
	}

	state := &c.datapathPassthroughReport
	fields := []struct {
		name     string
		total    uint64
		delta    uint64
		baseline *atomic.Uint64
	}{
		{name: "stateless_tcp_passthrough", total: snap.StatelessTCPPassthrough, baseline: &state.statelessTCPPassthrough},
		{name: "frag_tail_passed", total: snap.FragTailPassed, baseline: &state.fragTailPassed},
	}
	moved := false
	for i := range fields {
		base := fields[i].baseline.Load()
		if fields[i].total < base {
			// The counter went backwards: the map behind it was replaced, or
			// this snapshot came back zeroed. Re-baseline instead of reporting
			// a wrapped-around delta, and stay silent for this interval: its
			// traffic is not measurable, and the new map's running total is in
			// the next line.
			fields[i].baseline.Store(fields[i].total)
			continue
		}
		fields[i].delta = fields[i].total - base
		if fields[i].delta != 0 {
			moved = true
		}
	}

	if !state.primed.Swap(true) {
		// First observation: adopt the counters silently. They may carry the
		// traffic of every generation that shared this map, which is not this
		// interval's passthrough.
		for i := range fields {
			fields[i].baseline.Store(fields[i].total)
		}
		state.lastReportTime.Store(now.UnixNano())
		return
	}
	if !moved {
		return
	}

	nowNano := now.UnixNano()
	if last := state.lastReportTime.Load(); last != 0 && nowNano-last < int64(datapathPassthroughReportInterval) {
		// Inside the pacing window: keep accumulating. Only an emitted line
		// consumes the baselines, so this interval is carried into the next one.
		return
	}
	state.lastReportTime.Store(nowNano)
	logFields := make(logrus.Fields, 2*len(fields))
	for i := range fields {
		logFields[fields[i].name] = fields[i].delta
		logFields[fields[i].name+"_total"] = fields[i].total
		fields[i].baseline.Store(fields[i].total)
	}

	// Debug, not warn: these counters describe a by-design steady state
	// (established flows of a pre-restart connection keep being forwarded
	// without conn state for as long as they live), so a busy router keeps
	// the counter moving indefinitely and a warn here pages the operator
	// about healthy behaviour. The magnitude stays inspectable at
	// --log-level debug, and the authoritative numbers live in
	// bpf_stats_map either way.
	c.log.WithFields(logFields).Log(logrus.DebugLevel, "datapath passthrough: the datapath forwarded packets without a routing decision. Established TCP whose "+
		"flow has no cached conn state is what every pre-existing flow does after a restart, and a non-initial fragment carries no L4 "+
		"header to route on; both are by design. The fields are this interval's count plus the running total, and this line stops as soon "+
		"as the counters do")
}
