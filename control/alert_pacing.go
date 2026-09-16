/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// pacedAlert collapses a condition that stays true across many maintenance
// ticks, packets or queries into at most one log line per cooldown, while
// still reporting how many times the condition was observed. A sustained
// condition (a map that stays above its capacity threshold, a counter read
// that keeps failing) would otherwise write one line per tick for as long as
// it lasts, which buries the transition lines an operator can act on. Dropping
// the repeats silently is not an option either: the repeats are the only
// evidence that the condition never cleared. The observation count keeps them
// visible as the magnitude the operator actually needs.
type pacedAlert struct {
	lastEmitNano atomic.Int64
	observations atomic.Uint64
}

// observe records one observation of the condition and reports whether this
// observation should be logged, together with the number of observations seen
// so far (including this one). The first observation always logs, so a
// condition that happens exactly once is never suppressed, and a later
// observation logs again once cooldown has elapsed since the last emitted
// line, so the count in the message keeps growing while the condition lasts.
func (a *pacedAlert) observe(now time.Time, cooldown time.Duration) (observations uint64, emit bool) {
	observations = a.observations.Add(1)
	nowNano := now.UnixNano()
	last := a.lastEmitNano.Load()
	if last != 0 && nowNano-last < int64(cooldown) {
		return observations, false
	}
	if !a.lastEmitNano.CompareAndSwap(last, nowNano) {
		return observations, false
	}
	return observations, true
}

// udpIngressWarnLogInterval paces the per-packet UDP ingress warnings for
// conditions that outlive the packet that reported them: a routing-tuple
// lookup that fails for a destination keeps failing for every packet of every
// flow to that destination, and the same is true for a handlePkt error caused
// by persistent state. Every emitted line carries the number of packets the
// condition has been seen on, so the interval between two lines is a magnitude
// and not a gap.
const udpIngressWarnLogInterval = 30 * time.Second

// logUdpRoutingTupleFailure reports a routing-tuple lookup failure for a
// non-DNS destination. The destination keeps missing from the routing map
// until the datapath state that owns it changes, so the failure repeats for
// every packet of every flow to it; the pace plus the packet count keeps the
// magnitude without one line per packet.
func (c *ControlPlane) logUdpRoutingTupleFailure(err error) {
	if c == nil || c.log == nil || err == nil {
		return
	}
	packets, emit := c.udpRoutingTupleWarnAlert.observe(time.Now(), udpIngressWarnLogInterval)
	if !emit {
		return
	}
	c.log.Warnf("No AddrPort presented: %v (packets=%d, reporting at most one line per %v)",
		err, packets, udpIngressWarnLogInterval)
}

// logUdpDNSRoutingTupleFailure reports the same lookup failure for a DNS
// destination. It keeps its own pace: DNS lookups miss the routing map during
// a reload window by design, and that expected condition must not pace out the
// report of a non-DNS destination that never resolves.
func (c *ControlPlane) logUdpDNSRoutingTupleFailure(src, dst netip.AddrPort, err error) {
	if c == nil || c.log == nil || err == nil {
		return
	}
	packets, emit := c.udpDNSRoutingTupleWarnAlert.observe(time.Now(), udpIngressWarnLogInterval)
	if !emit {
		return
	}
	c.log.WithFields(logrus.Fields{
		"src":     src.String(),
		"dst":     dst.String(),
		"packets": packets,
	}).WithError(err).Warn("UDP routing tuple lookup failed for DNS; fallback to userspace routing")
}

// logUdpHandlePktFailure reports a handlePkt error that is not the expected
// reload-window routing-epoch ownership loss. Such an error repeats for every
// later packet of the affected flow, so it gets the same treatment as the
// expected condition: one paced line carrying the number of packets.
func (c *ControlPlane) logUdpHandlePktFailure(err error) {
	if c == nil || c.log == nil || err == nil {
		return
	}
	packets, emit := c.udpHandlePktWarnAlert.observe(time.Now(), udpIngressWarnLogInterval)
	if !emit {
		return
	}
	c.log.Warnf("handlePkt: %v (packets=%d, reporting at most one line per %v)",
		err, packets, udpIngressWarnLogInterval)
}

// mapCapacityAlertCooldown paces the "map at N% capacity" warnings. A BPF map
// that is above the threshold stays above the threshold for as long as the
// load that filled it lasts, and the janitor revisits each map every 1s..30s,
// so an unpaced warning repeats for hours and is indistinguishable from the
// transition the operator needs to see.
const mapCapacityAlertCooldown = time.Minute

// logMapCapacityAlert reports one above-threshold observation of a janitor map
// through the map's own pace. name is the janitor operation the message is
// attributed to, matching the prefix the unpaced warnings used.
func (c *ControlPlane) logMapCapacityAlert(alert *pacedAlert, name string, usagePercent float64, entries int) {
	if c == nil || c.log == nil || alert == nil {
		return
	}
	observations, emit := alert.observe(time.Now(), mapCapacityAlertCooldown)
	if !emit {
		// The count is not lost: it is carried by the next emitted line.
		return
	}
	c.log.Warnf("%s: map at %.1f%% capacity (%d entries; observed %d times, reporting at most one line per %v)",
		name, usagePercent, entries, observations, mapCapacityAlertCooldown)
}
