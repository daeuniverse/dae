/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/control"
)

// windowFixture drives a tracker with a controllable clock and counter table.
type windowFixture struct {
	tracker  *flowWindowTracker
	now      time.Time
	counters map[string][2]uint64
}

func newWindowFixture(now time.Time) *windowFixture {
	fixture := &windowFixture{now: now, counters: map[string][2]uint64{}}
	fixture.tracker = newFlowWindowTracker(func(yield func(control.FlowByteCounter)) {
		for id, value := range fixture.counters {
			yield(control.FlowByteCounter{ID: id, UploadBytes: value[0], DownloadBytes: value[1]})
		}
	})
	fixture.tracker.now = func() time.Time { return fixture.now }
	return fixture
}

func (f *windowFixture) advance(d time.Duration) {
	f.now = f.now.Add(d)
}

func (f *windowFixture) set(id string, upload, download uint64) {
	f.counters[id] = [2]uint64{upload, download}
}

// snapshotOf builds the flow view a listing would have read at the same time.
func (f *windowFixture) snapshotOf(id string, startedAt time.Time) control.SessionFlowSnapshot {
	counters := f.counters[id]
	return control.SessionFlowSnapshot{ID: id, HasBytes: true, StartedAt: startedAt, UploadBytes: counters[0], DownloadBytes: counters[1]}
}

func TestFlowWindowMeasuresTrailingWindow(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	started := fixture.now.Add(-time.Hour)
	fixture.set("f_1", 0, 1_000)
	flow := fixture.snapshotOf("f_1", started)

	// The first request has no baseline yet, so the window stays unknown.
	if measured := fixture.tracker.measure([]control.SessionFlowSnapshot{flow}, 10*time.Second); len(measured) != 0 {
		t.Fatalf("measured = %v, want nothing before a baseline exists", measured)
	}
	fixture.tracker.sampleOnce()

	fixture.advance(10 * time.Second)
	fixture.set("f_1", 0, 1_500)
	fixture.tracker.sampleOnce()

	fixture.advance(10 * time.Second)
	fixture.set("f_1", 100, 1_800)
	flow = fixture.snapshotOf("f_1", started)
	measured := fixture.tracker.measure([]control.SessionFlowSnapshot{flow}, 10*time.Second)
	if got := measured["f_1"]; got.upload != 100 || got.download != 300 {
		t.Fatalf("window bytes = %+v, want the delta since the sample one window back", got)
	}
}

func TestFlowWindowYoungFlowReportsItsCounters(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	fixture.set("f_new", 10, 900)
	flow := fixture.snapshotOf("f_new", fixture.now.Add(-5*time.Second))

	measured := fixture.tracker.measure([]control.SessionFlowSnapshot{flow}, time.Minute)
	// A flow younger than the window has moved exactly its counters within it.
	if got := measured["f_new"]; got.upload != 10 || got.download != 900 {
		t.Fatalf("window bytes = %+v, want the whole counter of a young flow", got)
	}
}

func TestFlowWindowUnknownWithoutBaseline(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	fixture.set("f_old", 10, 900)
	flow := fixture.snapshotOf("f_old", fixture.now.Add(-time.Hour))

	if measured := fixture.tracker.measure([]control.SessionFlowSnapshot{flow}, time.Minute); len(measured) != 0 {
		t.Fatalf("measured = %v, want an unknown window", measured)
	}
}

func TestFlowWindowRejectsStaleBaseline(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	started := fixture.now.Add(-time.Hour)
	fixture.set("f_1", 0, 1_000)
	fixture.tracker.measure([]control.SessionFlowSnapshot{fixture.snapshotOf("f_1", started)}, 10*time.Second)
	fixture.tracker.sampleOnce()

	// The only sample is far older than the window, so subtracting it would
	// report a span nobody asked for.
	fixture.advance(time.Minute)
	fixture.set("f_1", 0, 9_000)
	measured := fixture.tracker.measure([]control.SessionFlowSnapshot{fixture.snapshotOf("f_1", started)}, 10*time.Second)
	if len(measured) != 0 {
		t.Fatalf("measured = %v, want the stale baseline rejected", measured)
	}
}

func TestFlowWindowRejectsCounterRegression(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	started := fixture.now.Add(-time.Hour)
	fixture.set("f_1", 0, 1_000)
	fixture.tracker.measure([]control.SessionFlowSnapshot{fixture.snapshotOf("f_1", started)}, 10*time.Second)
	fixture.tracker.sampleOnce()

	fixture.advance(10 * time.Second)
	fixture.set("f_1", 0, 500)
	fixture.tracker.sampleOnce()

	fixture.advance(10 * time.Second)
	fixture.set("f_1", 0, 200)
	measured := fixture.tracker.measure([]control.SessionFlowSnapshot{fixture.snapshotOf("f_1", started)}, 10*time.Second)
	if len(measured) != 0 {
		t.Fatalf("measured = %v, want a replaced connection to stay unknown", measured)
	}
}

func TestFlowWindowSamplerStopsWhenIdle(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	fixture.set("f_1", 0, 10)
	fixture.tracker.measure([]control.SessionFlowSnapshot{fixture.snapshotOf("f_1", fixture.now)}, 10*time.Second)
	if interval := fixture.tracker.sampleOnce(); interval <= 0 {
		t.Fatalf("interval = %v, want a positive cadence", interval)
	}
	if len(fixture.tracker.rings) != 1 {
		t.Fatalf("rings = %d, want one observed flow", len(fixture.tracker.rings))
	}

	fixture.advance(flowWindowDemandIdle + time.Second)
	if interval := fixture.tracker.sampleOnce(); interval != flowWindowMaxInterval {
		t.Fatalf("interval = %v, want the idle cadence", interval)
	}
	if fixture.tracker.rings != nil {
		t.Fatalf("rings = %d, want history dropped once nobody reads a window", len(fixture.tracker.rings))
	}
}

func TestFlowWindowIntervalCoversTheLongestWindow(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	flow := control.SessionFlowSnapshot{ID: "f_1", HasBytes: true}
	for _, tc := range []struct {
		window time.Duration
		want   time.Duration
	}{
		{3 * time.Second, flowWindowMinInterval},
		{60 * time.Second, 4 * time.Second},
		{300 * time.Second, flowWindowMaxInterval},
	} {
		fixture.tracker.measure([]control.SessionFlowSnapshot{flow}, tc.window)
		if got := fixture.tracker.intervalLocked(); got != tc.want {
			t.Fatalf("interval for %v = %v, want %v", tc.window, got, tc.want)
		}
	}
}

func TestSortConnectionFlowsByCounters(t *testing.T) {
	flows := []control.SessionFlowSnapshot{
		{ID: "a", HasBytes: true, UploadBytes: 1, DownloadBytes: 10},
		{ID: "b", HasBytes: true, UploadBytes: 2, DownloadBytes: 20},
		{ID: "unknown"},
		{ID: "d", HasBytes: true, UploadBytes: 3, DownloadBytes: 5},
	}
	order := func(field, direction string) []string {
		sorted := append([]control.SessionFlowSnapshot(nil), flows...)
		sortConnectionFlows(sorted, field, direction, nil)
		ids := make([]string, 0, len(sorted))
		for _, flow := range sorted {
			ids = append(ids, flow.ID)
		}
		return ids
	}
	for _, tc := range []struct {
		field, direction string
		want             []string
	}{
		{"download", "desc", []string{"b", "a", "d", "unknown"}},
		{"download", "asc", []string{"d", "a", "b", "unknown"}},
		{"upload", "desc", []string{"d", "b", "a", "unknown"}},
		{"total", "desc", []string{"b", "a", "d", "unknown"}},
	} {
		got := order(tc.field, tc.direction)
		if len(got) != len(tc.want) {
			t.Fatalf("%s %s = %v, want %v", tc.field, tc.direction, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%s %s = %v, want %v", tc.field, tc.direction, got, tc.want)
			}
		}
	}
}

func TestSortConnectionFlowsByWindowBytes(t *testing.T) {
	flows := []control.SessionFlowSnapshot{
		{ID: "a", HasBytes: true, UploadBytes: 1, DownloadBytes: 10},
		{ID: "b", HasBytes: true, UploadBytes: 2, DownloadBytes: 20},
		{ID: "no-window", HasBytes: true},
	}
	windows := map[string]flowWindowBytes{"a": {upload: 5, download: 100}, "b": {upload: 50, download: 10}}

	sorted := append([]control.SessionFlowSnapshot(nil), flows...)
	sortConnectionFlows(sorted, "window_download", "desc", windows)
	if sorted[0].ID != "a" || sorted[1].ID != "b" || sorted[2].ID != "no-window" {
		t.Fatalf("window_download order = %v", []string{sorted[0].ID, sorted[1].ID, sorted[2].ID})
	}

	sorted = append([]control.SessionFlowSnapshot(nil), flows...)
	sortConnectionFlows(sorted, "window_upload", "asc", windows)
	if sorted[0].ID != "a" || sorted[1].ID != "b" || sorted[2].ID != "no-window" {
		t.Fatalf("window_upload order = %v", []string{sorted[0].ID, sorted[1].ID, sorted[2].ID})
	}

	sorted = append([]control.SessionFlowSnapshot(nil), flows...)
	sortConnectionFlows(sorted, "window_total", "desc", windows)
	if sorted[0].ID != "a" || sorted[1].ID != "b" || sorted[2].ID != "no-window" {
		t.Fatalf("window_total order = %v", []string{sorted[0].ID, sorted[1].ID, sorted[2].ID})
	}
}

func TestSelectConnectionFlowsKeepsTheSortedHead(t *testing.T) {
	flows := []control.SessionFlowSnapshot{
		{ID: "tcp-1", Network: "tcp", HasBytes: true, DownloadBytes: 30},
		{ID: "udp-1", Network: "udp"},
		{ID: "tcp-2", Network: "tcp", HasBytes: true, DownloadBytes: 20},
		{ID: "tcp-3", Network: "tcp", HasBytes: true, DownloadBytes: 10},
	}
	tcpFlows, udpFlows, truncated := selectConnectionFlows(flows, 2)
	if len(tcpFlows) != 2 || tcpFlows[0].ID != "tcp-1" || tcpFlows[1].ID != "tcp-2" {
		t.Fatalf("tcp flows = %+v, want the first two matches", tcpFlows)
	}
	if len(udpFlows) != 1 || udpFlows[0].ID != "udp-1" || !truncated {
		t.Fatalf("udp flows = %+v truncated = %v", udpFlows, truncated)
	}
}

func TestConnectionOfAttachesWindowBytes(t *testing.T) {
	provider := &nativeAPIProvider{connectionBytes: true}
	flow := control.SessionFlowSnapshot{ID: "f_1", Network: "tcp", HasBytes: true, UploadBytes: 7, DownloadBytes: 9}

	without := provider.connectionOf(flow, nil)
	if without.UploadWindowBytes != nil || without.DownloadWindowBytes != nil {
		t.Fatalf("unmeasured connection carries window bytes: %+v", without)
	}

	with := provider.connectionOf(flow, map[string]flowWindowBytes{"f_1": {upload: 3, download: 4}})
	if with.UploadWindowBytes == nil || *with.UploadWindowBytes != "3" {
		t.Fatalf("upload_window_bytes = %v, want 3", with.UploadWindowBytes)
	}
	if with.DownloadWindowBytes == nil || *with.DownloadWindowBytes != "4" {
		t.Fatalf("download_window_bytes = %v, want 4", with.DownloadWindowBytes)
	}
}

// The window bytes come from the same counters `disable_connection_bytes`
// suppresses, so a listing that hides the counters must not leak them through
// the window fields.
func TestConnectionWindowAbsentWhenBytesDisabled(t *testing.T) {
	provider := &nativeAPIProvider{connectionBytes: false}
	flow := control.SessionFlowSnapshot{ID: "f_1", Network: "tcp", HasBytes: true, UploadBytes: 7, DownloadBytes: 9}
	connection := provider.connectionOf(flow, map[string]flowWindowBytes{"f_1": {upload: 3, download: 4}})
	if connection.UploadWindowBytes != nil || connection.DownloadWindowBytes != nil {
		t.Fatalf("window bytes leaked while counters are disabled: %+v", connection)
	}
}

// A daemon without an active generation still answers a windowed listing: the
// sampler observes nothing instead of failing the request.
func TestFlowWindowsTolerateMissingGeneration(t *testing.T) {
	provider := &nativeAPIProvider{}
	tracker := provider.flowWindows()
	if tracker == nil || tracker != provider.flowWindows() {
		t.Fatal("the provider must keep one tracker")
	}
	tracker.measure([]control.SessionFlowSnapshot{{ID: "f_1", HasBytes: true, StartedAt: time.Now()}}, time.Second)
	if interval := tracker.sampleOnce(); interval <= 0 {
		t.Fatalf("interval = %v, want a positive cadence", interval)
	}
}

func TestFlowWindowDemandWakesSampler(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	fixture.tracker.measure(nil, time.Second)
	select {
	case <-fixture.tracker.wake:
	default:
		t.Fatal("new window demand did not wake the sampler")
	}
	fixture.tracker.measure(nil, time.Second)
	select {
	case <-fixture.tracker.wake:
		t.Fatal("repeated polling woke the sampler unnecessarily")
	default:
	}
}

// A dashboard that polls at its own cadence works without the sampler: the
// request itself is an observation, so the second poll measures the interval
// between the two polls.
func TestFlowWindowMeasuresBetweenPolls(t *testing.T) {
	fixture := newWindowFixture(time.Unix(1_700_000_000, 0))
	started := fixture.now.Add(-time.Hour)
	fixture.set("f_1", 0, 1_000)

	flows := []control.SessionFlowSnapshot{fixture.snapshotOf("f_1", started)}
	if measured := fixture.tracker.measure(flows, 20*time.Second); len(measured) != 0 {
		t.Fatalf("first poll = %v, want an unknown window", measured)
	}

	fixture.advance(20 * time.Second)
	fixture.set("f_1", 0, 4_000)
	flows = []control.SessionFlowSnapshot{fixture.snapshotOf("f_1", started)}
	measured := fixture.tracker.measure(flows, 20*time.Second)
	if got := measured["f_1"]; got.download != 3_000 {
		t.Fatalf("second poll = %+v, want the 3000 bytes between the polls", got)
	}
}
