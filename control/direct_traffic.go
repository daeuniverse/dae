/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

// This file is the userspace half of the datapath's direct-traffic counters.
//
// A direct (non-proxied) flow never reaches userspace: the datapath returns it
// from the TC hook without a redirect, so the relay byte counters in
// runtime_stats.go cannot see it. The kernel counts those bytes instead
// (direct_traffic_map in control/kern/tproxy.c) and this file turns the
// absolute per-CPU totals into interval deltas that feed the same runtime stats
// store the relay uses, so rate and total share one calculation.
//
// The bytes land in runtime.traffic and, through directTrafficCounters, in the
// builtin "direct" row of /api/v1/runtime/outbounds. Without that attribution
// the direct row was always zero and sum(runtime/outbounds) could never match
// runtime.traffic.bytes, which is what made the totals look wrong next to the
// per-group breakdown. This is a deliberate extension of the contract's
// "visible traffic only" note (api-standardize, runtime-status.md): the row
// now reports userspace payload bytes for must_direct flows plus kernel link
// bytes for pass-through flows, and the two units are never summed into one
// figure inside a single flow.
//
// /api/v1/runtime still reports traffic.observed_by = "mixed" and additionally
// splits the total under traffic.planes.{userspace,kernel_direct}, so a reader
// that needs one coherent unit can pick a plane instead of trusting the sum.
//
// Deliberate omissions, all documented rather than papered over:
//   - the figures are link bytes (L2 header included on *_l2 attachments),
//     while the relay counts payload bytes, so the two must never be summed
//     into one number;
//   - TCP retransmissions are counted once per transmitted packet;
//   - a flow that predates a restart has no conn_state at all, so its
//     established packets are counted as BPF_STATS_STATELESS_TCP_PASSTHROUGH
//     instead and never reach these counters;
//   - ICMP, non-initial fragments and other non-TCP/UDP pass-throughs are not
//     counted;
//   - short-lived UDP (direct DNS) creates no conn_state, so its download
//     direction is not counted while its upload direction is;
//   - when conn_state_map is full the TCP direct fallback counts only the SYN,
//     because the packets after it have no entry to recognise;
//   - a flow the WAN opened towards this host counts its inbound bytes as
//     download once the reply path has flagged the flow, so the very first
//     inbound packet is not counted;
//   - the download side cannot be matched through conn_state alone on a NAT
//     gateway: SNAT rewrites the destination of a reply to the WAN address, so
//     reversing its tuple never hits the entry the LAN ingress created (the
//     LAN-egress hook sees the restored tuple, but a bridged LAN forwards
//     through its member ports and its egress qdisc only ever sees the host's
//     own traffic). The datapath therefore keeps a second, NAT-independent
//     index keyed on the remote endpoint plus the local port, which SNAT
//     preserves. A gateway that has to remap the local port because two hosts
//     picked the same one loses the association, and that flow's download is
//     not counted;
//   - that index is an LRU: a flow idle long enough to be evicted stops being
//     recognised in the reply direction until its LAN side sends again;
//   - the direct_passthrough flag is never cleared when a tuple is republished
//     with a proxy decision. is_direct_conn_state guards against a stale flag
//     by also requiring a DIRECT routing shape, but a republish that keeps a
//     DIRECT outbound while sending the flow to userspace (a non-zero direct
//     mark on a local socket) is not representable there.

import (
	"sync/atomic"

	ob "github.com/daeuniverse/dae/component/outbound"
)

// directTrafficCounters is the process-level counter set behind the builtin
// "direct" row of runtime/outbounds. attachOutboundCounters binds it from the
// process-lifetime registry, so the row survives reloads exactly like the
// configured groups do.
var directTrafficCounters atomic.Pointer[ob.Counters]

func setDirectTrafficCounters(counters *ob.Counters) {
	directTrafficCounters.Store(counters)
}

// Direct traffic counter keys. Mirror enum direct_traffic_key in
// control/kern/tproxy.c; TestDirectTrafficKeysParityWithKernelSource pins the
// values.
const (
	directTrafficUploadBytes   uint32 = 0
	directTrafficDownloadBytes uint32 = 1
)

// directTrafficSnapshot is the absolute value of the datapath's direct-traffic
// counters at one read.
type directTrafficSnapshot struct {
	UploadBytes   uint64
	DownloadBytes uint64
}

// readDirectTrafficCounters sums the PERCPU_ARRAY. A nil map or a failed
// lookup yields the zero value: these counters are observational, so a read
// failure must degrade the panel and never the datapath.
func readDirectTrafficCounters(bpf *bpfObjects) directTrafficSnapshot {
	var snap directTrafficSnapshot
	if bpf == nil || bpf.DirectTrafficMap == nil {
		return snap
	}
	read := func(key uint32) uint64 {
		var perCPU []uint64
		if err := bpf.DirectTrafficMap.Lookup(key, &perCPU); err != nil {
			return 0
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		return sum
	}
	snap.UploadBytes = read(directTrafficUploadBytes)
	snap.DownloadBytes = read(directTrafficDownloadBytes)
	return snap
}

// directTrafficAccountant turns the absolute kernel counters into interval
// deltas. It is owned by bpfMaintenanceRuntime, which survives generation
// handoffs, so the running total is retained across reloads exactly like the
// outbound counters.
type directTrafficAccountant struct {
	primed bool
	last   directTrafficSnapshot
}

// advance folds one absolute sample into the accountant and returns the delta
// since the previous sample.
//
// The first sample is adopted as the baseline instead of being reported, which
// keeps a process-lifetime map total from appearing as one huge interval. If a
// value shrinks the map was recreated (fresh datapath state), so the baseline
// is rebased rather than producing an underflow; the userspace totals keep
// their accumulated value.
func (a *directTrafficAccountant) advance(snap directTrafficSnapshot) (upload, download uint64) {
	if !a.primed {
		a.primed = true
		a.last = snap
		return 0, 0
	}
	if snap.UploadBytes < a.last.UploadBytes ||
		snap.DownloadBytes < a.last.DownloadBytes {
		a.last = directTrafficSnapshot{}
	}
	upload = snap.UploadBytes - a.last.UploadBytes
	download = snap.DownloadBytes - a.last.DownloadBytes
	a.last = snap
	return upload, download
}

// record samples the counters and publishes the delta.
//
// It must be called at RuntimeSampleInterval or faster: runtimeStats buckets
// are 250ms wide, so a slower reader would dump several buckets of bytes into
// the current one, producing a rate spike followed by zeros.
//
// It writes through currentRuntimeStatsStore, the same entry point the relay
// uses. Writing a specific generation's store instead made the counters stop
// silently whenever that generation was no longer the maintenance target: the
// bytes kept accumulating in the map while nothing published them.
func (a *directTrafficAccountant) record(bpf *bpfObjects) {
	a.publish(a.advance(readDirectTrafficCounters(bpf)))
}

// publish attributes one interval of pass-through bytes to the builtin direct
// row and to the process-lifetime totals.
func (a *directTrafficAccountant) publish(upload, download uint64) {
	if upload == 0 && download == 0 {
		return
	}
	// Attribute the bytes to the builtin "direct" outbound so the per-group
	// breakdown adds up to the total, then add them to the process-lifetime
	// totals with their own plane tag.
	if counters := directTrafficCounters.Load(); counters != nil {
		counters.AddUpload(upload)
		counters.AddDownload(download)
	}
	currentRuntimeStatsStore().recordDirect(upload, download)
}
