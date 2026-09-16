/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"net"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

// Dae event types mirror enum dae_event_type in control/kern/tproxy.c.
const (
	daeEventBlocked = iota
	daeEventUdpConnOverflow
	daeEventTcpConnOverflow
	daeEventBlockedAlive
	// daeEventRedirectRebindRejected: a competing publisher tried to steal a
	// reply binding that is still fresh.
	daeEventRedirectRebindRejected
	// daeEventSynRebindRejected: a pure SYN was refused rewrite of a live
	// flow's routing metadata.
	daeEventSynRebindRejected
	// daeEventReservedStatelessTcpPassthrough (6) and
	// daeEventReservedFragTailPassed (7) are reserved and never emitted. Both
	// described a by-design passthrough whose normal steady state (established
	// TCP of a pre-existing flow after a restart, a forwarded fragment tail)
	// cannot be reported per event: their rate key was shared by every
	// affected flow, so the ringbuf delivered one sample per second for as
	// long as the state lasted. The datapath counts them per packet in
	// bpf_stats_map instead, and ControlPlane.reportDatapathPassthroughSummary
	// reports the interval delta. The numbers stay reserved so the remaining
	// types keep their wire values, and
	// TestDaeEventTypeNumbersMatchKernelSource pins that numbering.
	daeEventReservedStatelessTcpPassthrough
	daeEventReservedFragTailPassed
	// daeEventRedirectUpdateFailed: redirect_track could not store a reply
	// binding. The matching bpf_stats_map counter separates a full
	// map from any other update error.
	daeEventRedirectUpdateFailed
	// daeEventSynRebindRerouted: a pure SYN re-created a live flow's cached
	// routing because the flow belonged to an older routing epoch or datapath
	// generation. This is the expected, counted outcome of a staged reload
	// handoff that let a connection drain: the connection is not cut, and the
	// next SYN moves it onto the current rules.
	daeEventSynRebindRerouted
)

// daeEvent mirrors struct dae_event in control/kern/tproxy.c. The kernel writes
// native-endian scalars into the 72-byte ringbuf record.
type daeEvent struct {
	Timestamp uint64
	Type      uint32
	Pid       uint32
	Pname     [16]byte
	Outbound  uint8
	L4proto   uint8
	Sip       [4]uint32
	Dip       [4]uint32
	Sport     uint16
	Dport     uint16
}

func parseDaeEvent(b []byte) daeEvent {
	return parseDaeEventWithABI(nativeBpfABI, b)
}

func parseDaeEventWithABI(abi bpfHostABI, b []byte) (e daeEvent) {
	if len(b) < 72 {
		return e
	}
	e.Timestamp = abi.uint64(b[0:8])
	e.Type = abi.uint32(b[8:12])
	e.Pid = abi.uint32(b[12:16])
	copy(e.Pname[:], b[16:32])
	e.Outbound = b[32]
	e.L4proto = b[33]
	for i := range 4 {
		e.Sip[i] = abi.uint32(b[36+4*i : 40+4*i])
		e.Dip[i] = abi.uint32(b[52+4*i : 56+4*i])
	}
	e.Sport = abi.uint16(b[68:70])
	e.Dport = abi.uint16(b[70:72])
	return e
}

// startEventRingbufReader consumes kernel ringbuf events and forwards
// conn-state overflow events to the conn state janitor, making the janitor
// event-driven instead of purely polling. The reader blocks in ReadInto; it
// is woken by Close when the owning BPF runtime stops.
//
// The reader re-opens the same runtime-owned map after transient errors. A
// fresh BPF object set gets a separate runtime; shared reloads keep this reader
// alive. Stub builds simply park and retain periodic cleanup as the fallback.
func (r *bpfMaintenanceRuntime) readEvents() {
	var reader *ringbuf.Reader
	defer func() {
		if reader != nil {
			_ = reader.Close()
		}
	}()
	for {
		select {
		case <-r.stop:
			return
		default:
		}
		if reader == nil {
			if r.bpf == nil || r.bpf.EventRingbuf == nil {
				select {
				case <-r.stop:
					return
				case <-time.After(100 * time.Millisecond):
					continue
				}
			}
			opened, err := ringbuf.NewReader(r.bpf.EventRingbuf)
			if err != nil {
				select {
				case <-r.stop:
					return
				case <-time.After(100 * time.Millisecond):
					continue
				}
			}
			reader = opened
			r.reader.Store(opened)
			select {
			case <-r.stop:
				_ = reader.Close()
				r.reader.Store(nil)
				reader = nil
				return
			default:
			}
		}
		record := ringbuf.Record{}
		if err := reader.ReadInto(&record); err != nil {
			_ = reader.Close()
			reader = nil
			r.reader.Store(nil)
			continue
		}
		target := r.active.Load()
		if target == nil {
			continue
		}
		ev := parseDaeEvent(record.RawSample)
		switch ev.Type {
		case daeEventUdpConnOverflow, daeEventTcpConnOverflow:
			r.requestOverflow(target)
		case daeEventRedirectUpdateFailed:
			// redirect_track could not store a reply binding. Reply traffic
			// for that flow is lost until the map drains, so run a janitor
			// round (which also cleans redirect_track sooner under
			// pressure) in addition to the warning below.
			r.requestOverflow(target)
			reportDatapathAnomaly(target, &ev, "redirect_track update failed: reply binding not stored")
		case daeEventRedirectRebindRejected:
			reportDatapathAnomaly(target, &ev, "reply binding kept against a competing publisher (still fresh)")
		case daeEventSynRebindRejected:
			reportDatapathAnomaly(target, &ev, "pure SYN refused rewrite of a live flow's routing metadata")
		case daeEventSynRebindRerouted:
			reportDatapathFlowEvent(target, &ev, "pure SYN moved a live flow that outlived a rules change onto the current routing epoch")
		case daeEventReservedStatelessTcpPassthrough, daeEventReservedFragTailPassed:
			// Both types are reserved and never emitted; see the type table
			// above. The matching bpf_stats_map counters reach the operator
			// through reportDatapathPassthroughSummary instead, so an event
			// of these types can only mean the binaries disagree (the kernel
			// object and this Go side ship together): report that as the ABI
			// drift it is, without reviving the per-event warning.
			logrus.Debugf("reserved datapath event type %d received; kernel object and userspace disagree", ev.Type)
		case daeEventBlockedAlive:
			// Kernel blocked a packet because the selected outbound is
			// not alive (wan_outbound_is_alive == false). Userspace never
			// sees this flow (it is dropped before tproxy), so the normal
			// dial-error path can't trigger resuscitation here. Trigger a
			// group-level resuscitation probe so recovery does not wait
			// for the next periodic health check. Resuscitate is
			// rate-limited per group; the kernel additionally rate-limits
			// event emission per outbound (1/s), so this cannot storm the
			// probe workers.
			target.handleBlockedAliveEvent(&ev)
		default:
			// Unknown types cannot be acted on, but they must not be dropped
			// in silence: kernel events and this binary ship together, so an
			// unknown type means the ABI drifted.
			logrus.Debugf("ignoring unknown datapath event type %d", ev.Type)
		}
	}
}

// reportDatapathAnomaly logs a kernel-reported datapath anomaly. The kernel
// rate-limits each anomaly event type to one emission per second, but the rate
// key is shared by every flow of that type: the bound is on the log, not on the
// condition, and the tuple carried here is one arbitrary sample of it. That is
// why only genuine anomalies belong on this path: a by-design steady state is
// counted per packet and summarised by reportDatapathPassthroughSummary
// instead. The per-packet counters in bpf_stats_map remain the authoritative
// count either way.
func reportDatapathAnomaly(c *ControlPlane, ev *daeEvent, msg string) {
	reportDatapathEventAt(c, logrus.WarnLevel, ev, msg)
}

// reportDatapathFlowEvent logs a per-flow datapath decision that is by
// design rather than an anomaly — the live flow whose next pure SYN adopts
// the current routing epoch after a staged reload handoff. Under the
// grading rule (per-flow or per-connection decisions are debug-level) it
// carries the same tuple at debug level; the bpf_stats_map counter
// BPF_STATS_REBIND_REROUTED_AFTER_EPOCH_CHANGE remains the authoritative
// count, and the health tick can surface it to operators regardless of
// log level.
func reportDatapathFlowEvent(c *ControlPlane, ev *daeEvent, msg string) {
	reportDatapathEventAt(c, logrus.DebugLevel, ev, msg)
}

// reportDatapathEventAt is the shared formatter for kernel datapath event
// reports; level is the only thing the two outlets disagree on.
func reportDatapathEventAt(c *ControlPlane, level logrus.Level, ev *daeEvent, msg string) {
	if c == nil || c.log == nil {
		return
	}
	c.log.Logf(level, "datapath anomaly: %s (type=%d pid=%d outbound=%d l4proto=%d %s:%d > %s:%d)",
		msg, ev.Type, ev.Pid, ev.Outbound, ev.L4proto,
		netIPString(ev.Sip), netPortString(ev.Sport),
		netIPString(ev.Dip), netPortString(ev.Dport))
}

// netPortString renders a port from a ringbuf record. The kernel copies the
// network-order port field verbatim, so it is re-encoded with the same ABI
// before being decoded as big-endian.
func netPortString(port uint16) uint16 {
	var b [2]byte
	nativeBpfABI.putUint16(b[:], port)
	return binary.BigEndian.Uint16(b[:])
}

// netIPString renders the kernel event address pair. The kernel stores the
// address words in host byte order inside the ringbuf record, so they are
// re-encoded with the same ABI before formatting. IPv4-mapped addresses (the
// kernel's canonical IPv4 form) are printed as plain IPv4.
func netIPString(addr [4]uint32) string {
	var b [16]byte
	for i, word := range addr {
		nativeBpfABI.putUint32(b[4*i:4*i+4], word)
	}
	return net.IP(b[:]).String()
}

// handleBlockedAliveEvent reacts to a kernel DAE_EVENT_BLOCKED_ALIVE by
// probing the affected outbound group for the blocked protocol family.
func (c *ControlPlane) handleBlockedAliveEvent(ev *daeEvent) {
	if c == nil || c.core == nil {
		return
	}
	idx := int(ev.Outbound)
	state := c.controlPlaneGenerationState
	if idx >= len(state.outbounds) {
		return
	}
	group := state.outbounds[idx]
	if group == nil {
		return
	}
	networkType := &dialer.NetworkType{}
	switch ev.L4proto {
	case unix.IPPROTO_TCP:
		networkType.L4Proto = consts.L4ProtoStr_TCP
	case unix.IPPROTO_UDP:
		networkType.L4Proto = consts.L4ProtoStr_UDP
	default:
		// Kernel only emits BLOCKED_ALIVE for TCP/UDP; unknown values are
		// ignored rather than defaulting to a probe of the wrong family.
		return
	}
	networkType.IpVersion = consts.IpVersionStr_4 // probe both; Resuscitate fans out
	group.Resuscitate(networkType)
}
