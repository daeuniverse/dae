/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

// NodeLatencySnapshot describes the latest observable latency status for one node link.
type NodeLatencySnapshot struct {
	Link      string
	LatencyMs *int32
	Alive     bool
	Message   string
	CheckedAt time.Time
}

// TriggerLatencyChecks asks dialers to refresh their TCP latency samples.
func (c *ControlPlane) TriggerLatencyChecks() {
	if c == nil {
		return
	}
	for _, group := range c.outbounds {
		if group == nil {
			continue
		}
		for _, d := range group.Dialers {
			if d == nil {
				continue
			}
			d.NotifyCheck()
		}
	}
}

// ActiveTCPConnections returns the number of currently tracked incoming TCP connections.
func (c *ControlPlane) ActiveTCPConnections() (n int) {
	if c == nil {
		return 0
	}
	c.inConnections.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// SnapshotNodeLatencies returns one best-effort latency snapshot per unique node link.
func (c *ControlPlane) SnapshotNodeLatencies() []NodeLatencySnapshot {
	if c == nil {
		return nil
	}

	latenciesByLink := make(map[string]NodeLatencySnapshot)
	for _, group := range c.outbounds {
		if group == nil {
			continue
		}
		for _, d := range group.Dialers {
			if d == nil || d.Property() == nil || d.Property().Link == "" {
				continue
			}

			snapshot := bestNodeLatencySnapshotForDialer(d)
			if existing, ok := latenciesByLink[snapshot.Link]; !ok || preferNodeLatencySnapshot(snapshot, existing) {
				latenciesByLink[snapshot.Link] = snapshot
			}
		}
	}

	results := make([]NodeLatencySnapshot, 0, len(latenciesByLink))
	for _, snapshot := range latenciesByLink {
		results = append(results, snapshot)
	}
	return results
}

func bestNodeLatencySnapshotForDialer(d *dialer.Dialer) NodeLatencySnapshot {
	link := ""
	if d != nil && d.Property() != nil {
		link = d.Property().Link
	}
	snapshot := NodeLatencySnapshot{
		Link:      link,
		Alive:     false,
		Message:   "no latency result",
		CheckedAt: time.Time{},
	}

	checkTypes := []*dialer.NetworkType{
		{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_4,
		},
		{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_6,
		},
	}

	for _, networkType := range checkTypes {
		candidate, ok := nodeLatencySnapshotForNetwork(d, link, networkType)
		if !ok {
			continue
		}
		if snapshot.LatencyMs == nil || preferNodeLatencySnapshot(candidate, snapshot) {
			snapshot = candidate
		}
	}

	return snapshot
}

func nodeLatencySnapshotForNetwork(d *dialer.Dialer, link string, networkType *dialer.NetworkType) (NodeLatencySnapshot, bool) {
	currentAlive := d.MustGetAlive(networkType)
	observation := d.SnapshotLastProbe(networkType)
	if !observation.CheckedAt.IsZero() {
		return snapshotFromProbeObservation(link, currentAlive, observation), true
	}

	// Backward-compatible fallback for inherited snapshots that predate the
	// explicit probe observation field. The next real health check will replace
	// this synthesized view with an accurate CheckedAt timestamp.
	latency, ok := d.MustGetLatencies10(networkType).LastLatency()
	if !ok {
		return NodeLatencySnapshot{}, false
	}
	alive := d.MustGetAlive(networkType)
	return snapshotFromProbeObservation(link, alive, dialer.DialerProbeObservationSnapshot{
		Alive:      alive,
		Latency:    latency,
		HasLatency: true,
		Message:    dialer.FormatLatencyMessage(&dialer.LatencyProbeResult{Alive: alive, Latency: latency}),
	}), true
}

func snapshotFromProbeObservation(link string, currentAlive bool, observation dialer.DialerProbeObservationSnapshot) NodeLatencySnapshot {
	snapshot := NodeLatencySnapshot{
		Link:      link,
		Alive:     currentAlive,
		CheckedAt: observation.CheckedAt,
	}
	if observation.HasLatency {
		latencyMs := int32(observation.Latency.Milliseconds())
		snapshot.LatencyMs = &latencyMs
		if currentAlive {
			snapshot.Message = dialer.FormatLatencyMessage(&dialer.LatencyProbeResult{
				Alive:   true,
				Latency: observation.Latency,
			})
		} else if observation.Alive || observation.Message == "" {
			snapshot.Message = "unavailable"
		}
	} else {
		snapshot.Message = observation.Message
	}
	if snapshot.Message == "" {
		snapshot.Message = "no latency result"
	}
	return snapshot
}

func preferNodeLatencySnapshot(next NodeLatencySnapshot, current NodeLatencySnapshot) bool {
	if next.Alive != current.Alive {
		return next.Alive
	}
	if next.LatencyMs != nil && current.LatencyMs == nil {
		return true
	}
	if next.LatencyMs == nil {
		return false
	}
	if current.LatencyMs == nil {
		return true
	}
	if *next.LatencyMs != *current.LatencyMs {
		return *next.LatencyMs < *current.LatencyMs
	}
	return next.CheckedAt.After(current.CheckedAt)
}
