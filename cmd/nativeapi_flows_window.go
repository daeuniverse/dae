/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"sync"
	"time"

	"github.com/daeuniverse/dae/control"
)

const (
	// flowWindowCapacity is how many observations one flow keeps. The ring
	// spans the window it is asked about, so a read always has a baseline at
	// least one window old.
	flowWindowCapacity = 16
	// flowWindowMinInterval keeps short windows responsive; the interval grows
	// with the window so the ring covers it without keeping more samples.
	flowWindowMinInterval = time.Second
	flowWindowMaxInterval = 20 * time.Second
	// flowWindowDemandIdle drops the observations of a window nobody asked for
	// in this long. Sampling only runs while a caller waits on it.
	flowWindowDemandIdle = 2 * time.Minute
)

// flowWindowSample is one observation of a flow's cumulative counters.
type flowWindowSample struct {
	atUnixNano int64
	upload     uint64
	download   uint64
}

type flowWindowRing struct {
	samples []flowWindowSample // oldest first
}

func (r *flowWindowRing) append(sample flowWindowSample) {
	r.samples = append(r.samples, sample)
	if len(r.samples) > flowWindowCapacity {
		r.samples = append(r.samples[:0], r.samples[len(r.samples)-flowWindowCapacity:]...)
	}
}

// baseline returns the newest sample no later than target. A ring that has
// only newer samples, or whose newest usable sample is more than one sampling
// interval older than target, has no baseline: the delta would cover a span the
// caller did not ask for.
func (r *flowWindowRing) baseline(target time.Time, tolerance time.Duration) (flowWindowSample, bool) {
	var best flowWindowSample
	found := false
	for _, sample := range r.samples {
		if sample.atUnixNano > target.UnixNano() {
			continue
		}
		if !found || sample.atUnixNano > best.atUnixNano {
			best, found = sample, true
		}
	}
	if !found {
		return flowWindowSample{}, false
	}
	if target.Sub(time.Unix(0, best.atUnixNano)) > tolerance {
		return flowWindowSample{}, false
	}
	return best, true
}

// flowWindowBytes is the traffic one flow moved in a trailing window.
type flowWindowBytes struct {
	upload   uint64
	download uint64
}

// flowWindowTracker keeps short history of per-flow counters so a listing can
// report trailing-window bytes. The counters live in the datapath; this only
// observes them, which is why a window is as accurate as the sampling interval
// and why a flow without a baseline reports an unknown window rather than zero.
type flowWindowTracker struct {
	mu     sync.Mutex
	rings  map[string]*flowWindowRing
	demand map[int64]time.Time // window seconds asked for -> last request

	// observe walks the live flows' cumulative counters.
	observe func(yield func(control.FlowByteCounter))
	now     func() time.Time
	wake    chan struct{}
}

func newFlowWindowTracker(observe func(yield func(control.FlowByteCounter))) *flowWindowTracker {
	return &flowWindowTracker{
		observe: observe,
		now:     time.Now,
		wake:    make(chan struct{}, 1),
	}
}

// flowWindows returns the provider's tracker, starting its sampler once.
func (p *nativeAPIProvider) flowWindows() *flowWindowTracker {
	p.flowsOnce.Do(func() {
		p.flowWindow = newFlowWindowTracker(func(yield func(control.FlowByteCounter)) {
			plane, err := p.activeControlPlane()
			if err != nil {
				return
			}
			plane.FlowByteCounters(yield)
		})
		go p.flowWindow.run()
	})
	return p.flowWindow
}

// measure registers demand for a window and returns the bytes each flow moved
// in it. Flows whose window is unknown are absent from the map.
func (t *flowWindowTracker) measure(flows []control.SessionFlowSnapshot, window time.Duration) map[string]flowWindowBytes {
	if t == nil || window <= 0 {
		return nil
	}
	now := t.now()
	t.mu.Lock()
	if t.demand == nil {
		t.demand = make(map[int64]time.Time)
	}
	for seconds, requestedAt := range t.demand {
		if now.Sub(requestedAt) > flowWindowDemandIdle {
			delete(t.demand, seconds)
		}
	}
	previousInterval := t.intervalLocked()
	wakeSampler := len(t.demand) == 0
	// Demand is registered even for an empty match: the next poll of the same
	// window must still find a baseline.
	t.demand[int64(window/time.Second)] = now
	wakeSampler = wakeSampler || t.intervalLocked() < previousInterval
	measured := make(map[string]flowWindowBytes, len(flows))
	tolerance := t.intervalLocked()
	for _, flow := range flows {
		if !flow.HasBytes {
			continue
		}
		// Seed the first observation from the request itself: waiting for the
		// sampler would make the first windowed poll after an idle period come
		// back empty.
		if t.rings == nil {
			t.rings = make(map[string]*flowWindowRing)
		}
		if t.rings[flow.ID] == nil {
			ring := &flowWindowRing{}
			ring.append(flowWindowSample{atUnixNano: now.UnixNano(), upload: flow.UploadBytes, download: flow.DownloadBytes})
			t.rings[flow.ID] = ring
		}
		upload, download, ok := t.windowLocked(flow, window, now, tolerance)
		if ok {
			measured[flow.ID] = flowWindowBytes{upload: upload, download: download}
		}
	}
	t.mu.Unlock()
	if wakeSampler {
		select {
		case t.wake <- struct{}{}:
		default:
		}
	}
	return measured
}

func (t *flowWindowTracker) windowLocked(flow control.SessionFlowSnapshot, window time.Duration, now time.Time, tolerance time.Duration) (uint64, uint64, bool) {
	target := now.Add(-window)
	if ring := t.rings[flow.ID]; ring != nil {
		if sample, ok := ring.baseline(target, tolerance); ok {
			// A counter that went backwards means the connection was replaced;
			// the delta would be nonsense, so the window stays unknown.
			if flow.UploadBytes >= sample.upload && flow.DownloadBytes >= sample.download {
				return flow.UploadBytes - sample.upload, flow.DownloadBytes - sample.download, true
			}
			return 0, 0, false
		}
	}
	// A flow younger than the window has moved exactly its counters within it.
	if !flow.StartedAt.IsZero() && flow.StartedAt.After(target) {
		return flow.UploadBytes, flow.DownloadBytes, true
	}
	return 0, 0, false
}

// run samples on the cadence the demanded windows need. An idle tracker only
// wakes up; it does not walk the flow table.
func (t *flowWindowTracker) run() {
	timer := time.NewTimer(flowWindowMinInterval)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
		case <-t.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		timer.Reset(t.sampleOnce())
	}
}

// sampleOnce records one observation per live flow and returns how long to wait
// before the next one.
func (t *flowWindowTracker) sampleOnce() time.Duration {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for seconds, at := range t.demand {
		if now.Sub(at) > flowWindowDemandIdle {
			delete(t.demand, seconds)
		}
	}
	if len(t.demand) == 0 {
		// Nobody is reading a window: keep no history and stop walking flows.
		t.rings = nil
		return flowWindowMaxInterval
	}
	interval := t.intervalLocked()
	if t.observe == nil {
		return interval
	}
	if t.rings == nil {
		t.rings = make(map[string]*flowWindowRing)
	}
	sample := flowWindowSample{atUnixNano: now.UnixNano()}
	live := make(map[string]struct{}, len(t.rings))
	t.observe(func(counter control.FlowByteCounter) {
		ring := t.rings[counter.ID]
		if ring == nil {
			ring = &flowWindowRing{}
			t.rings[counter.ID] = ring
		}
		sample.upload, sample.download = counter.UploadBytes, counter.DownloadBytes
		ring.append(sample)
		live[counter.ID] = struct{}{}
	})
	for id := range t.rings {
		if _, ok := live[id]; !ok {
			delete(t.rings, id)
		}
	}
	return interval
}

// intervalLocked spaces observations so the ring covers the largest window in
// demand. Capacity-1 intervals span one window exactly. Callers that read
// different windows share the longest one's cadence, so a much shorter window
// read alongside a much longer one is only accurate to that cadence.
func (t *flowWindowTracker) intervalLocked() time.Duration {
	var longest int64
	for seconds := range t.demand {
		if seconds > longest {
			longest = seconds
		}
	}
	if longest <= 0 {
		return flowWindowMaxInterval
	}
	interval := time.Duration(longest) * time.Second / (flowWindowCapacity - 1)
	if interval < flowWindowMinInterval {
		interval = flowWindowMinInterval
	}
	if interval > flowWindowMaxInterval {
		interval = flowWindowMaxInterval
	}
	return interval
}
