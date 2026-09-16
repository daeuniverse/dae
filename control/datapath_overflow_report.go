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

// This file owns the operator-visible outlet of bpf_stats_map. The kernel
// advances one counter per datapath condition, and the ringbuf warnings are
// deliberately reduced to a one-per-second glimpse of a condition that can last
// as long as the flows it describes, so the counters are the only thing that can
// answer "how much". Two properties keep the report honest, and both were
// missing while the health check compared the counters against their lifetime
// totals:
//
//   - The report describes the interval since the previous line, not the
//     lifetime total. bpf_stats_map is a shared handle (bpf_utils.go copies it
//     into every generation's object set), so its counters never return to zero:
//     a single overflow ever observed made "overflow > 0" permanently true and
//     re-alerted on every cooldown expiry for the life of the process, and a
//     lifetime total above the pressure threshold re-raised "CRITICAL ...
//     overflow=%d" the same way, presenting a historical count as pressure
//     happening now.
//   - The line is emitted only in an interval that moved. A condition that stops
//     stops being reported, which is what keeps a datapath that never recovers
//     from costing a line per cadence forever.
const (
	// datapathOverflowReportInterval paces the line. The health tick runs every
	// 5s, far too fast for a condition that lasts as long as the flows it
	// describes: that would trade a per-event warning for a per-tick one. 30s
	// keeps the magnitude visible while capping a sustained condition at
	// 120 lines/hour.
	datapathOverflowReportInterval = 30 * time.Second
	// datapathHeavyOverflowDelta is the number of conn-state overflow events one
	// interval must accumulate before the report is raised to error level: at
	// that rate the map is not merely full, it is rejecting flows continuously.
	datapathHeavyOverflowDelta = 100
)

// datapathOverflowField is one counter in the report. level is what this
// counter's movement means on its own; heavyDelta (0 = never escalates) raises
// it to error level when a single interval accumulates more than the threshold.
// The name, the grading and the counter live in one row so the delta
// computation, the classification and the emitted fields cannot drift apart.
type datapathOverflowField struct {
	name       string
	level      logrus.Level
	heavyDelta uint64
	total      uint64
	delta      uint64
	baseline   *atomic.Uint64
}

// controlPlaneDatapathOverflowReport holds the counter values the last emitted
// line consumed. The baselines advance only when a line is actually emitted, so
// a paced interval is carried into the next line instead of being dropped.
// primed records that the baselines were established, because the first
// observation of a shared counter must not present its lifetime total as an
// interval.
type controlPlaneDatapathOverflowReport struct {
	primed         atomic.Bool
	lastReportTime atomic.Int64

	udpConnOverflow                atomic.Uint64
	tcpConnOverflow                atomic.Uint64
	redirectOverflow               atomic.Uint64
	redirectUpdateFailed           atomic.Uint64
	redirectRebindRejected         atomic.Uint64
	synRebindRejected              atomic.Uint64
	parseUnsupportedL4             atomic.Uint64
	unsolicitedUDPSeen             atomic.Uint64
	sockmarkFallback               atomic.Uint64
	eventDrop                      atomic.Uint64
	rebindReroutedAfterEpochChange atomic.Uint64
}

// datapathOverflowFields binds every bpf_stats_map counter this report owns to
// its baseline, computing the deltas on the way. The two by-design passthrough
// counters are deliberately absent: they are published on the same health tick
// by reportDatapathPassthroughSummary and would otherwise be reported twice.
func (r *controlPlaneDatapathOverflowReport) datapathOverflowFields(snap bpfStatsSnapshot, udpOverflow, tcpOverflow uint64) []datapathOverflowField {
	fields := []datapathOverflowField{
		{name: "udp_conn_overflow", level: logrus.WarnLevel, heavyDelta: datapathHeavyOverflowDelta, total: udpOverflow, baseline: &r.udpConnOverflow},
		{name: "tcp_conn_overflow", level: logrus.WarnLevel, heavyDelta: datapathHeavyOverflowDelta, total: tcpOverflow, baseline: &r.tcpConnOverflow},
		{name: "redirect_overflow", level: logrus.WarnLevel, total: snap.RedirectOverflow, baseline: &r.redirectOverflow},
		{name: "redirect_update_failed", level: logrus.WarnLevel, total: snap.RedirectUpdateFailed, baseline: &r.redirectUpdateFailed},
		{name: "event_drop", level: logrus.WarnLevel, total: snap.EventDrop, baseline: &r.eventDrop},
		{name: "redirect_rebind_rejected", level: logrus.DebugLevel, total: snap.RedirectRebindRejected, baseline: &r.redirectRebindRejected},
		{name: "syn_rebind_rejected", level: logrus.DebugLevel, total: snap.SynRebindRejected, baseline: &r.synRebindRejected},
		{name: "rebind_rerouted_after_epoch_change", level: logrus.DebugLevel, total: snap.RebindReroutedAfterEpochChange, baseline: &r.rebindReroutedAfterEpochChange},
		{name: "parse_unsupported_l4", level: logrus.DebugLevel, total: snap.ParseUnsupportedL4, baseline: &r.parseUnsupportedL4},
		{name: "unsolicited_udp_seen", level: logrus.DebugLevel, total: snap.UnsolicitedUDPSeen, baseline: &r.unsolicitedUDPSeen},
		{name: "sockmark_fallback", level: logrus.DebugLevel, total: snap.SockmarkFallback, baseline: &r.sockmarkFallback},
	}
	for i := range fields {
		base := fields[i].baseline.Load()
		if fields[i].total < base {
			// The counter went backwards: the map behind it was replaced, so
			// this interval is not comparable with the baseline. Re-baseline
			// instead of reporting a wrapped-around delta.
			fields[i].baseline.Store(fields[i].total)
			continue
		}
		fields[i].delta = fields[i].total - base
	}
	return fields
}

// consume advances every baseline to the value the emitted line reported.
func (r *controlPlaneDatapathOverflowReport) consume(fields []datapathOverflowField) {
	for i := range fields {
		fields[i].baseline.Store(fields[i].total)
	}
}

// classifyDatapathOverflowInterval grades one interval of counter activity.
// logrus levels are ordered most severe first, so the lowest level wins and a
// heavy conn-state overflow cannot be masked by a debug-level counter. moved is
// false when no counter advanced at all, which is the normal steady state and
// must stay silent.
func classifyDatapathOverflowInterval(fields []datapathOverflowField) (level logrus.Level, moved bool) {
	level = logrus.DebugLevel
	for i := range fields {
		if fields[i].delta == 0 {
			continue
		}
		moved = true
		fieldLevel := fields[i].level
		if fields[i].heavyDelta > 0 && fields[i].delta > fields[i].heavyDelta {
			fieldLevel = logrus.ErrorLevel
		}
		if fieldLevel < level {
			level = fieldLevel
		}
	}
	return level, moved
}

// datapathOverflowMessage explains the line at the level it carries.
func datapathOverflowMessage(level logrus.Level) string {
	switch level {
	case logrus.ErrorLevel:
		return "CRITICAL: the conn-state maps are rejecting flows continuously " +
			"(udp_conn_overflow/tcp_conn_overflow are this interval's rejections, not a lifetime total). " +
			"Untracked flows fall back to slower paths and can lose their reply binding; " +
			"check conn_state_map capacity and the connection timeouts"
	case logrus.WarnLevel:
		return "datapath resource exhaustion or event loss in this interval: a full conn-state map, " +
			"a reply binding redirect_track could not store, or a datapath event dropped by a full event ringbuf. " +
			"Each field is what that counter advanced since the previous line, with its lifetime total next to it; " +
			"check map capacity, conn-state timeouts and the event ringbuf size"
	default:
		return "datapath counters with no per-event warning advanced in this interval (non-TCP/UDP packets, " +
			"unsolicited WAN UDP, socket-mark fallback, rebind rejections, routing-epoch reroutes). " +
			"Reported at debug level: the rebind counters have their own per-event warning and the rest is " +
			"hot-path per-packet detail"
	}
}

// reportDatapathOverflowInterval publishes one interval of datapath counter
// activity. It is called from the health tick with the counters that tick read,
// and it is the reason those counters are read at all: before this, four of them
// were compared against their lifetime totals and the remaining ones were read,
// stored in a snapshot and never shown to anyone.
//
// Nothing is reported silently: a counter that advanced is in the line, either
// because it grades the line (resource exhaustion or heavy pressure) or as a
// field of a debug-level line, and its lifetime total is always next to its
// interval delta.
func (c *ControlPlane) reportDatapathOverflowInterval(now time.Time, snap bpfStatsSnapshot, udpOverflow, tcpOverflow, connStateCapacity uint64) {
	if c == nil || c.log == nil {
		return
	}

	state := &c.datapathOverflowReport
	fields := state.datapathOverflowFields(snap, udpOverflow, tcpOverflow)
	level, moved := classifyDatapathOverflowInterval(fields)

	if !state.primed.Swap(true) {
		// First observation: the baselines are unknown, and the counters may
		// carry the traffic of every generation that shared this map. Adopting
		// them silently is the only honest start; the next interval is measured
		// from here.
		state.consume(fields)
		state.lastReportTime.Store(now.UnixNano())
		return
	}
	if !moved {
		return
	}

	nowNano := now.UnixNano()
	if last := state.lastReportTime.Load(); last != 0 && nowNano-last < int64(datapathOverflowReportInterval) {
		// Inside the pacing window: keep accumulating. The baselines are only
		// advanced when a line is emitted, so the next report carries this
		// interval too instead of dropping it.
		return
	}
	state.lastReportTime.Store(nowNano)
	state.consume(fields)

	logFields := make(logrus.Fields, 2*len(fields)+1)
	for _, f := range fields {
		logFields[f.name] = f.delta
		logFields[f.name+"_total"] = f.total
	}
	if connStateCapacity > 0 {
		logFields["conn_state_map_capacity"] = connStateCapacity
	}
	c.log.WithFields(logFields).Log(level, datapathOverflowMessage(level))
}
