/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/sirupsen/logrus"
)

func setNodeLatencyTestAliveState(t *testing.T, d *componentdialer.Dialer, idx int, alive bool) {
	t.Helper()

	snapshot := d.HealthSnapshot()
	snapshot.Collections[idx].Alive = alive
	d.RestoreHealthSnapshot(snapshot)
}

func setNodeLatencyTestProbeObservation(t *testing.T, d *componentdialer.Dialer, idx int, observation componentdialer.DialerProbeObservationSnapshot) {
	t.Helper()

	snapshot := d.HealthSnapshot()
	snapshot.Collections[idx].LastProbe = observation
	d.RestoreHealthSnapshot(snapshot)
}

func newNodeLatencyTestDialer(t *testing.T, name, link string) *componentdialer.Dialer {
	t.Helper()

	log := logrus.New()
	log.SetOutput(io.Discard)

	d := componentdialer.NewDialer(
		direct.SymmetricDirect,
		&componentdialer.GlobalOption{
			Log:            log,
			CheckInterval:  time.Minute,
			CheckTolerance: 0,
		},
		componentdialer.InstanceOption{DisableCheck: true},
		&componentdialer.Property{
			Property: D.Property{
				Name: name,
				Link: link,
			},
		},
	)
	t.Cleanup(func() {
		_ = d.Close()
	})
	return d
}

func TestControlPlaneSnapshotNodeLatenciesPrefersLowerLatencyPerLink(t *testing.T) {
	const sharedLink = "trojan://node-a"

	faster := newNodeLatencyTestDialer(t, "node-a-fast", sharedLink)
	slower := newNodeLatencyTestDialer(t, "node-a-slow", sharedLink)

	tcp4 := &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
	}
	faster.MustGetLatencies10(tcp4).AppendLatency(15 * time.Millisecond)
	slower.MustGetLatencies10(tcp4).AppendLatency(40 * time.Millisecond)
	expectedCheckedAt := time.Unix(1_700_000_010, 0)
	setNodeLatencyTestProbeObservation(t, faster, componentdialer.IdxTcp4, componentdialer.DialerProbeObservationSnapshot{
		CheckedAt:  expectedCheckedAt,
		Alive:      true,
		Latency:    15 * time.Millisecond,
		HasLatency: true,
		Message:    "15ms",
	})
	setNodeLatencyTestProbeObservation(t, slower, componentdialer.IdxTcp4, componentdialer.DialerProbeObservationSnapshot{
		CheckedAt:  expectedCheckedAt.Add(-time.Second),
		Alive:      true,
		Latency:    40 * time.Millisecond,
		HasLatency: true,
		Message:    "40ms",
	})

	plane := &ControlPlane{}
	plane.outbounds = []*outbound.DialerGroup{
		{
			Name:    "proxy",
			Dialers: []*componentdialer.Dialer{slower, faster},
		},
	}

	snapshots := plane.SnapshotNodeLatencies()
	if len(snapshots) != 1 {
		t.Fatalf("SnapshotNodeLatencies() len = %d, want 1", len(snapshots))
	}
	snapshot := snapshots[0]
	if snapshot.Link != sharedLink {
		t.Fatalf("snapshot link = %q, want %q", snapshot.Link, sharedLink)
	}
	if snapshot.LatencyMs == nil {
		t.Fatal("snapshot LatencyMs = nil, want non-nil")
	}
	if got, want := *snapshot.LatencyMs, int32(15); got != want {
		t.Fatalf("snapshot latency_ms = %d, want %d", got, want)
	}
	if !snapshot.Alive {
		t.Fatal("snapshot Alive = false, want true")
	}
	if got, want := snapshot.Message, "15ms"; got != want {
		t.Fatalf("snapshot message = %q, want %q", got, want)
	}
	if !snapshot.CheckedAt.Equal(expectedCheckedAt) {
		t.Fatalf("snapshot CheckedAt = %v, want %v", snapshot.CheckedAt, expectedCheckedAt)
	}
}

func TestBestNodeLatencySnapshotForDialerPrefersAliveFamilyOverLowerDeadLatency(t *testing.T) {
	d := newNodeLatencyTestDialer(t, "node-a", "trojan://node-a")

	tcp4 := &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
	}
	tcp6 := &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_6,
	}

	d.MustGetLatencies10(tcp4).AppendLatency(100 * time.Millisecond)
	d.MustGetLatencies10(tcp6).AppendLatency(50 * time.Millisecond)
	setNodeLatencyTestAliveState(t, d, componentdialer.IdxTcp4, true)
	setNodeLatencyTestAliveState(t, d, componentdialer.IdxTcp6, false)
	setNodeLatencyTestProbeObservation(t, d, componentdialer.IdxTcp4, componentdialer.DialerProbeObservationSnapshot{
		CheckedAt:  time.Unix(1_700_000_020, 0),
		Alive:      true,
		Latency:    100 * time.Millisecond,
		HasLatency: true,
		Message:    "100ms",
	})
	setNodeLatencyTestProbeObservation(t, d, componentdialer.IdxTcp6, componentdialer.DialerProbeObservationSnapshot{
		CheckedAt: time.Unix(1_700_000_021, 0),
		Alive:     false,
		Message:   "timeout",
	})

	snapshot := bestNodeLatencySnapshotForDialer(d)
	if snapshot.LatencyMs == nil {
		t.Fatal("snapshot LatencyMs = nil, want non-nil")
	}
	if got, want := *snapshot.LatencyMs, int32(100); got != want {
		t.Fatalf("snapshot latency_ms = %d, want %d", got, want)
	}
	if !snapshot.Alive {
		t.Fatal("snapshot Alive = false, want true")
	}
	if got, want := snapshot.Message, "100ms"; got != want {
		t.Fatalf("snapshot message = %q, want %q", got, want)
	}
}

func TestControlPlaneSnapshotNodeLatenciesPrefersAliveLinkOverLowerDeadLatency(t *testing.T) {
	const sharedLink = "trojan://node-a"

	deadButLower := newNodeLatencyTestDialer(t, "node-a-dead", sharedLink)
	aliveButHigher := newNodeLatencyTestDialer(t, "node-a-alive", sharedLink)

	tcp4 := &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
	}

	deadButLower.MustGetLatencies10(tcp4).AppendLatency(15 * time.Millisecond)
	aliveButHigher.MustGetLatencies10(tcp4).AppendLatency(30 * time.Millisecond)
	setNodeLatencyTestAliveState(t, deadButLower, componentdialer.IdxTcp4, false)
	setNodeLatencyTestAliveState(t, aliveButHigher, componentdialer.IdxTcp4, true)
	setNodeLatencyTestProbeObservation(t, deadButLower, componentdialer.IdxTcp4, componentdialer.DialerProbeObservationSnapshot{
		CheckedAt:  time.Unix(1_700_000_030, 0),
		Alive:      false,
		Latency:    15 * time.Millisecond,
		HasLatency: true,
		Message:    "15ms",
	})
	setNodeLatencyTestProbeObservation(t, aliveButHigher, componentdialer.IdxTcp4, componentdialer.DialerProbeObservationSnapshot{
		CheckedAt:  time.Unix(1_700_000_031, 0),
		Alive:      true,
		Latency:    30 * time.Millisecond,
		HasLatency: true,
		Message:    "30ms",
	})

	plane := &ControlPlane{}
	plane.outbounds = []*outbound.DialerGroup{
		{
			Name:    "proxy",
			Dialers: []*componentdialer.Dialer{deadButLower, aliveButHigher},
		},
	}

	snapshots := plane.SnapshotNodeLatencies()
	if len(snapshots) != 1 {
		t.Fatalf("SnapshotNodeLatencies() len = %d, want 1", len(snapshots))
	}
	snapshot := snapshots[0]
	if snapshot.LatencyMs == nil {
		t.Fatal("snapshot LatencyMs = nil, want non-nil")
	}
	if got, want := *snapshot.LatencyMs, int32(30); got != want {
		t.Fatalf("snapshot latency_ms = %d, want %d", got, want)
	}
	if !snapshot.Alive {
		t.Fatal("snapshot Alive = false, want true")
	}
	if got, want := snapshot.Message, "30ms"; got != want {
		t.Fatalf("snapshot message = %q, want %q", got, want)
	}
}

func TestControlPlaneSnapshotNodeLatenciesUsesMostRecentFailedProbeMessageWhenNoLatencyExists(t *testing.T) {
	d := newNodeLatencyTestDialer(t, "node-a", "trojan://node-a")

	setNodeLatencyTestAliveState(t, d, componentdialer.IdxTcp4, false)
	setNodeLatencyTestProbeObservation(t, d, componentdialer.IdxTcp4, componentdialer.DialerProbeObservationSnapshot{
		CheckedAt: time.Unix(1_700_000_040, 0),
		Alive:     false,
		Message:   "timeout",
	})

	plane := &ControlPlane{}
	plane.outbounds = []*outbound.DialerGroup{
		{
			Name:    "proxy",
			Dialers: []*componentdialer.Dialer{d},
		},
	}

	snapshots := plane.SnapshotNodeLatencies()
	if len(snapshots) != 1 {
		t.Fatalf("SnapshotNodeLatencies() len = %d, want 1", len(snapshots))
	}
	snapshot := snapshots[0]
	if snapshot.LatencyMs != nil {
		t.Fatalf("snapshot LatencyMs = %v, want nil", *snapshot.LatencyMs)
	}
	if snapshot.Alive {
		t.Fatal("snapshot Alive = true, want false")
	}
	if got, want := snapshot.Message, "timeout"; got != want {
		t.Fatalf("snapshot message = %q, want %q", got, want)
	}
}

func TestControlPlaneSnapshotNodeLatenciesUsesCurrentAliveStateOverStaleProbeAlive(t *testing.T) {
	d := newNodeLatencyTestDialer(t, "node-a", "trojan://node-a")

	tcp4 := &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
	}
	d.MustGetLatencies10(tcp4).AppendLatency(25 * time.Millisecond)
	setNodeLatencyTestAliveState(t, d, componentdialer.IdxTcp4, false)
	setNodeLatencyTestProbeObservation(t, d, componentdialer.IdxTcp4, componentdialer.DialerProbeObservationSnapshot{
		CheckedAt:  time.Unix(1_700_000_050, 0),
		Alive:      true,
		Latency:    25 * time.Millisecond,
		HasLatency: true,
		Message:    "25ms",
	})

	plane := &ControlPlane{}
	plane.outbounds = []*outbound.DialerGroup{
		{
			Name:    "proxy",
			Dialers: []*componentdialer.Dialer{d},
		},
	}

	snapshots := plane.SnapshotNodeLatencies()
	if len(snapshots) != 1 {
		t.Fatalf("SnapshotNodeLatencies() len = %d, want 1", len(snapshots))
	}
	snapshot := snapshots[0]
	if snapshot.Alive {
		t.Fatal("snapshot Alive = true, want false")
	}
	if got, want := snapshot.Message, "unavailable"; got != want {
		t.Fatalf("snapshot message = %q, want %q", got, want)
	}
}
