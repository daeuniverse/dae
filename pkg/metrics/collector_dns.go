/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package metrics

import (
	"sort"

	"github.com/prometheus/client_golang/prometheus"
)

type DnsCollector struct {
	state *State

	cacheEntries      *prometheus.Desc
	concurrencyInUse  *prometheus.Desc
	concurrencyLimit  *prometheus.Desc
	forwarderCache    *prometheus.Desc
	forwarderInFlight *prometheus.Desc
	queryTotal        *prometheus.Desc
	cacheHitTotal     *prometheus.Desc
	cacheLazyHitTotal *prometheus.Desc
	cacheMissTotal    *prometheus.Desc
	upstreamQuery     *prometheus.Desc
	upstreamErr       *prometheus.Desc
	rejectedTotal     *prometheus.Desc
	refusedTotal      *prometheus.Desc
	responseLatency   *prometheus.Desc
	upstreamLatency   *prometheus.Desc
}

func NewDnsCollector(state *State) *DnsCollector {
	return &DnsCollector{
		state: state,
		cacheEntries: prometheus.NewDesc(
			"dae_dns_cache_entries",
			"Current number of entries in the DNS response cache",
			nil,
			nil,
		),
		concurrencyInUse: prometheus.NewDesc(
			"dae_dns_concurrency_in_use",
			"The number of DNS query slots currently in use",
			nil,
			nil,
		),
		concurrencyLimit: prometheus.NewDesc(
			"dae_dns_concurrency_limit",
			"The maximum number of concurrent DNS queries allowed",
			nil,
			nil,
		),
		forwarderCache: prometheus.NewDesc(
			"dae_dns_forwarder_cache_entries",
			"Current number of cached DNS forwarder connections",
			nil,
			nil,
		),
		forwarderInFlight: prometheus.NewDesc(
			"dae_dns_forwarder_in_flight",
			"The number of DNS queries currently being forwarded to the upstream",
			[]string{"upstream"},
			nil,
		),
		queryTotal: prometheus.NewDesc(
			"dae_dns_query_total",
			"Total number of DNS queries handled by dae",
			nil,
			nil,
		),
		cacheHitTotal: prometheus.NewDesc(
			"dae_dns_cache_hit_total",
			"Total number of fresh DNS cache hits",
			nil,
			nil,
		),
		cacheLazyHitTotal: prometheus.NewDesc(
			"dae_dns_cache_lazy_hit_total",
			"Total number of stale DNS cache responses served while refreshing in background",
			nil,
			nil,
		),
		cacheMissTotal: prometheus.NewDesc(
			"dae_dns_cache_miss_total",
			"Total number of DNS cache misses",
			nil,
			nil,
		),
		upstreamQuery: prometheus.NewDesc(
			"dae_dns_upstream_query_total",
			"Total number of DNS upstream forwarding attempts",
			[]string{"upstream"},
			nil,
		),
		upstreamErr: prometheus.NewDesc(
			"dae_dns_upstream_err_total",
			"Total number of failed DNS upstream forwarding attempts",
			[]string{"upstream"},
			nil,
		),
		rejectedTotal: prometheus.NewDesc(
			"dae_dns_rejected_total",
			"Total number of rejected DNS responses",
			nil,
			nil,
		),
		refusedTotal: prometheus.NewDesc(
			"dae_dns_refused_total",
			"Total number of refused DNS responses due to overload protection",
			nil,
			nil,
		),
		responseLatency: prometheus.NewDesc(
			"dae_dns_response_latency_seconds",
			"End-to-end DNS handling latency in seconds",
			nil,
			nil,
		),
		upstreamLatency: prometheus.NewDesc(
			"dae_dns_upstream_latency_seconds",
			"DNS upstream forwarding latency in seconds",
			[]string{"upstream"},
			nil,
		),
	}
}

func (c *DnsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.cacheEntries
	ch <- c.concurrencyInUse
	ch <- c.concurrencyLimit
	ch <- c.forwarderCache
	ch <- c.forwarderInFlight
	ch <- c.queryTotal
	ch <- c.cacheHitTotal
	ch <- c.cacheLazyHitTotal
	ch <- c.cacheMissTotal
	ch <- c.upstreamQuery
	ch <- c.upstreamErr
	ch <- c.rejectedTotal
	ch <- c.refusedTotal
	ch <- c.responseLatency
	ch <- c.upstreamLatency
}

func (c *DnsCollector) Collect(ch chan<- prometheus.Metric) {
	if c.state == nil {
		return
	}
	cp := c.state.GetControlPlane()
	if cp == nil {
		return
	}
	dc := cp.GetDnsController()
	if dc == nil {
		return
	}

	ch <- prometheus.MustNewConstMetric(c.cacheEntries, prometheus.GaugeValue, float64(dc.CacheSize()))
	inUse, limit := dc.ConcurrencyInfo()
	ch <- prometheus.MustNewConstMetric(c.concurrencyInUse, prometheus.GaugeValue, float64(inUse))
	ch <- prometheus.MustNewConstMetric(c.concurrencyLimit, prometheus.GaugeValue, float64(limit))

	forwarderCount, inFlightByUpstream := dc.ForwarderCacheInfo()
	ch <- prometheus.MustNewConstMetric(c.forwarderCache, prometheus.GaugeValue, float64(forwarderCount))

	upstreams := make([]string, 0, len(inFlightByUpstream))
	for upstream := range inFlightByUpstream {
		upstreams = append(upstreams, upstream)
	}
	sort.Strings(upstreams)
	for _, upstream := range upstreams {
		ch <- prometheus.MustNewConstMetric(
			c.forwarderInFlight,
			prometheus.GaugeValue,
			float64(inFlightByUpstream[upstream]),
			upstream,
		)
	}

	counters := dc.DnsCountersSnapshot()
	ch <- prometheus.MustNewConstMetric(c.queryTotal, prometheus.CounterValue, float64(counters.QueryTotal))
	ch <- prometheus.MustNewConstMetric(c.cacheHitTotal, prometheus.CounterValue, float64(counters.CacheHitTotal))
	ch <- prometheus.MustNewConstMetric(c.cacheLazyHitTotal, prometheus.CounterValue, float64(counters.CacheLazyHitTotal))
	ch <- prometheus.MustNewConstMetric(c.cacheMissTotal, prometheus.CounterValue, float64(counters.CacheMissTotal))
	ch <- prometheus.MustNewConstMetric(c.rejectedTotal, prometheus.CounterValue, float64(counters.RejectedTotal))
	ch <- prometheus.MustNewConstMetric(c.refusedTotal, prometheus.CounterValue, float64(counters.RefusedTotal))

	latency := dc.DnsResponseLatencySnapshot()
	ch <- prometheus.MustNewConstHistogram(c.responseLatency, latency.Count, latency.Sum, latency.Buckets)

	upstreamSnapshot := dc.DnsUpstreamSnapshot()
	upstreamKeys := make([]string, 0, len(upstreamSnapshot))
	for upstream := range upstreamSnapshot {
		upstreamKeys = append(upstreamKeys, upstream)
	}
	sort.Strings(upstreamKeys)
	for _, upstream := range upstreamKeys {
		snapshot := upstreamSnapshot[upstream]
		ch <- prometheus.MustNewConstMetric(c.upstreamQuery, prometheus.CounterValue, float64(snapshot.QueryTotal), upstream)
		ch <- prometheus.MustNewConstMetric(c.upstreamErr, prometheus.CounterValue, float64(snapshot.ErrTotal), upstream)
		ch <- prometheus.MustNewConstHistogram(
			c.upstreamLatency,
			snapshot.Latency.Count,
			snapshot.Latency.Sum,
			snapshot.Latency.Buckets,
			upstream,
		)
	}
}
