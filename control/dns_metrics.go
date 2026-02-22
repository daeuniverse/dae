/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"math"
	"sync/atomic"
	"time"
)

var dnsLatencyHistogramBounds = []float64{
	0.001, 0.0025, 0.005, 0.01, 0.025, 0.05,
	0.1, 0.25, 0.5, 1, 2, 5,
}

type DnsHistogramSnapshot struct {
	Count   uint64
	Sum     float64
	Buckets map[float64]uint64
}

type DnsCountersSnapshot struct {
	QueryTotal         uint64
	CacheHitTotal      uint64
	CacheLazyHitTotal  uint64
	CacheMissTotal     uint64
	UpstreamQueryTotal uint64
	UpstreamErrTotal   uint64
	RejectedTotal      uint64
	RefusedTotal       uint64
}

type DnsUpstreamMetricsSnapshot struct {
	QueryTotal uint64
	ErrTotal   uint64
	Latency    DnsHistogramSnapshot
}

type dnsLatencyHistogram struct {
	count   atomic.Uint64
	sumBits atomic.Uint64
	buckets []atomic.Uint64 // +Inf bucket included at index len(dnsLatencyHistogramBounds)
}

type dnsUpstreamMetric struct {
	queryTotal atomic.Uint64
	errTotal   atomic.Uint64
	latency    *dnsLatencyHistogram
}

func newDnsLatencyHistogram() *dnsLatencyHistogram {
	return &dnsLatencyHistogram{
		buckets: make([]atomic.Uint64, len(dnsLatencyHistogramBounds)+1),
	}
}

func newDnsUpstreamMetric() *dnsUpstreamMetric {
	return &dnsUpstreamMetric{
		latency: newDnsLatencyHistogram(),
	}
}

func addAtomicFloat64(bits *atomic.Uint64, delta float64) {
	for {
		oldBits := bits.Load()
		newBits := math.Float64bits(math.Float64frombits(oldBits) + delta)
		if bits.CompareAndSwap(oldBits, newBits) {
			return
		}
	}
}

func (h *dnsLatencyHistogram) Observe(seconds float64) {
	if h == nil {
		return
	}
	if seconds < 0 {
		seconds = 0
	}
	idx := len(dnsLatencyHistogramBounds)
	for i, bound := range dnsLatencyHistogramBounds {
		if seconds <= bound {
			idx = i
			break
		}
	}
	h.buckets[idx].Add(1)
	h.count.Add(1)
	addAtomicFloat64(&h.sumBits, seconds)
}

func (h *dnsLatencyHistogram) Snapshot() DnsHistogramSnapshot {
	if h == nil {
		return DnsHistogramSnapshot{
			Buckets: map[float64]uint64{},
		}
	}
	buckets := make(map[float64]uint64, len(dnsLatencyHistogramBounds))
	var cumulative uint64
	for i, bound := range dnsLatencyHistogramBounds {
		cumulative += h.buckets[i].Load()
		buckets[bound] = cumulative
	}
	count := h.count.Load()
	if count < cumulative {
		count = cumulative
	}
	return DnsHistogramSnapshot{
		Count:   count,
		Sum:     math.Float64frombits(h.sumBits.Load()),
		Buckets: buckets,
	}
}

func (c *DnsController) initDnsMetricsState() {
	c.dnsMetricsInit.Do(func() {
		if c.dnsResponseLatency == nil {
			c.dnsResponseLatency = newDnsLatencyHistogram()
		}
	})
}

func (c *DnsController) getOrCreateDnsUpstreamMetric(upstream string) *dnsUpstreamMetric {
	c.initDnsMetricsState()
	if val, ok := c.dnsUpstreamMetrics.Load(upstream); ok {
		if metric, ok := val.(*dnsUpstreamMetric); ok {
			return metric
		}
	}
	created := newDnsUpstreamMetric()
	actual, loaded := c.dnsUpstreamMetrics.LoadOrStore(upstream, created)
	if loaded {
		if metric, ok := actual.(*dnsUpstreamMetric); ok {
			return metric
		}
	}
	return created
}

func (c *DnsController) observeDnsResponseLatency(latency time.Duration) {
	c.initDnsMetricsState()
	c.dnsResponseLatency.Observe(latency.Seconds())
}

func (c *DnsController) DnsCountersSnapshot() DnsCountersSnapshot {
	c.initDnsMetricsState()
	var upstreamQueryTotal uint64
	var upstreamErrTotal uint64
	c.dnsUpstreamMetrics.Range(func(_, value interface{}) bool {
		if metric, ok := value.(*dnsUpstreamMetric); ok {
			upstreamQueryTotal += metric.queryTotal.Load()
			upstreamErrTotal += metric.errTotal.Load()
		}
		return true
	})
	return DnsCountersSnapshot{
		QueryTotal:         c.dnsQueryTotal.Load(),
		CacheHitTotal:      c.dnsCacheHitTotal.Load(),
		CacheLazyHitTotal:  c.dnsCacheLazyHitTotal.Load(),
		CacheMissTotal:     c.dnsCacheMissTotal.Load(),
		UpstreamQueryTotal: upstreamQueryTotal,
		UpstreamErrTotal:   upstreamErrTotal,
		RejectedTotal:      c.dnsRejectedTotal.Load(),
		RefusedTotal:       c.dnsRefusedTotal.Load(),
	}
}

func (c *DnsController) DnsResponseLatencySnapshot() DnsHistogramSnapshot {
	c.initDnsMetricsState()
	return c.dnsResponseLatency.Snapshot()
}

func (c *DnsController) DnsUpstreamSnapshot() map[string]DnsUpstreamMetricsSnapshot {
	c.initDnsMetricsState()
	snapshot := make(map[string]DnsUpstreamMetricsSnapshot)
	c.dnsUpstreamMetrics.Range(func(key, value interface{}) bool {
		upstream, ok := key.(string)
		if !ok {
			return true
		}
		metric, ok := value.(*dnsUpstreamMetric)
		if !ok {
			return true
		}
		snapshot[upstream] = DnsUpstreamMetricsSnapshot{
			QueryTotal: metric.queryTotal.Load(),
			ErrTotal:   metric.errTotal.Load(),
			Latency:    metric.latency.Snapshot(),
		}
		return true
	})
	return snapshot
}
