/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"time"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
)

// OutboundCounterSnapshot is one outbound's counters at snapshot time.
type OutboundCounterSnapshot struct {
	Name              string
	Kind              string
	ActiveConnections int64
	TotalConnections  uint64
	UploadBytes       uint64
	DownloadBytes     uint64
	Errors            uint64
}

// OutboundCountersSnapshot is the whole runtime/outbounds projection.
type OutboundCountersSnapshot struct {
	ObservedAt   time.Time
	CounterSince time.Time
	Outbounds    []OutboundCounterSnapshot
}

// attachOutboundCounters binds the process-level counter registry to this
// generation's groups. Every generation built with the same group name gets
// the same counter pointer, which is what makes the counters survive reloads.
func (c *ControlPlane) attachOutboundCounters(registry *ob.CounterRegistry) {
	if c == nil || registry == nil {
		return
	}
	c.outboundCountersMu.Lock()
	defer c.outboundCountersMu.Unlock()
	if c.outboundCounters == registry && c.outboundCountersByIndex != nil {
		return
	}
	byIndex := make(map[uint8]*ob.Counters, len(c.outbounds))
	for i, group := range c.outbounds {
		if group == nil {
			continue
		}
		counters := registry.Acquire(group.Name)
		group.SetCounters(counters)
		if consts.OutboundIndex(i) == consts.OutboundDirect {
			// The datapath counts pass-through bytes that never reach the relay;
			// binding the direct row here is what lets that row report them.
			setDirectTrafficCounters(counters)
		}
		byIndex[uint8(i)] = counters
	}
	c.outboundCounters = registry
	c.outboundCountersByIndex = byIndex
}

// outboundCountersForIndex returns the counters attached to one outbound
// index, or nil when no registry is attached yet.
func (c *ControlPlane) outboundCountersForIndex(index consts.OutboundIndex) *ob.Counters {
	if c == nil {
		return nil
	}
	c.outboundCountersMu.RLock()
	defer c.outboundCountersMu.RUnlock()
	return c.outboundCountersByIndex[uint8(index)]
}

// outboundKind reports whether an outbound index is a builtin (direct/block)
// or a configured group.
func outboundKind(index consts.OutboundIndex) string {
	if index < consts.OutboundUserDefinedMin {
		return "builtin"
	}
	return "group"
}

// OutboundCountersSince reports the process-level boundary that
// runtime/outbounds and runtime.traffic share, so both resources answer
// "since when" with the same instant.
func (c *ControlPlane) OutboundCountersSince() time.Time {
	if c == nil {
		return time.Time{}
	}
	c.outboundCountersMu.RLock()
	defer c.outboundCountersMu.RUnlock()
	if c.outboundCounters == nil {
		return time.Time{}
	}
	return c.outboundCounters.Since()
}

// SnapshotOutboundCounters projects the per-outbound counters of this
// generation. Names are read from the generation's immutable outbound list and
// the counters from the process-level registry.
func (c *ControlPlane) SnapshotOutboundCounters() OutboundCountersSnapshot {
	observedAt := time.Now()
	if c == nil {
		return OutboundCountersSnapshot{ObservedAt: observedAt}
	}
	c.outboundCountersMu.RLock()
	registry := c.outboundCounters
	c.outboundCountersMu.RUnlock()
	if registry == nil {
		return OutboundCountersSnapshot{ObservedAt: observedAt}
	}

	snapshot := OutboundCountersSnapshot{
		ObservedAt:   observedAt,
		CounterSince: registry.Since(),
		Outbounds:    make([]OutboundCounterSnapshot, 0, len(c.outbounds)),
	}
	for i, group := range c.outbounds {
		if group == nil {
			continue
		}
		counters := registry.Lookup(group.Name)
		snapshot.Outbounds = append(snapshot.Outbounds, OutboundCounterSnapshot{
			Name:              group.Name,
			Kind:              outboundKind(consts.OutboundIndex(i)),
			ActiveConnections: counters.ActiveConnections(),
			TotalConnections:  counters.TotalConnections(),
			UploadBytes:       counters.UploadBytes(),
			DownloadBytes:     counters.DownloadBytes(),
			Errors:            counters.Errors(),
		})
	}
	return snapshot
}

// recordUploadTrafficFor accounts upload bytes both in the generation-bound
// runtime history and against the selected outbound. The counter pointer is
// resolved once per flow, so the byte path never re-enters the registry.
func (c *ControlPlane) recordUploadTrafficFor(counters *ob.Counters, n int64) {
	if n <= 0 {
		return
	}
	c.recordUploadTraffic(n)
	counters.AddUpload(uint64(n))
}

// recordDownloadTrafficFor is recordUploadTrafficFor for the reply direction.
func (c *ControlPlane) recordDownloadTrafficFor(counters *ob.Counters, n int64) {
	if n <= 0 {
		return
	}
	c.recordDownloadTraffic(n)
	counters.AddDownload(uint64(n))
}

// trafficRecordersFor binds the relay record callbacks to one outbound. The
// returned pair matches RelayTCPContextWithRecords' (download, upload) order.
func (c *ControlPlane) trafficRecordersFor(counters *ob.Counters) (download func(int64), upload func(int64)) {
	return func(n int64) { c.recordDownloadTrafficFor(counters, n) },
		func(n int64) { c.recordUploadTrafficFor(counters, n) }
}

// trafficRecordersForFlow is trafficRecordersFor plus per-flow byte counters,
// so /connections can report the bytes of one live flow.
func (c *ControlPlane) trafficRecordersForFlow(counters *ob.Counters, flow *FlowRuntime) (download func(int64), upload func(int64)) {
	return func(n int64) {
			c.recordDownloadTrafficFor(counters, n)
			if n > 0 && flow != nil {
				flow.downloadBytes.Add(uint64(n))
			}
		}, func(n int64) {
			c.recordUploadTrafficFor(counters, n)
			if n > 0 && flow != nil {
				flow.uploadBytes.Add(uint64(n))
			}
		}
}
