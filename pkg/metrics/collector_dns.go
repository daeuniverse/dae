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
	}
}

func (c *DnsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.cacheEntries
	ch <- c.concurrencyInUse
	ch <- c.concurrencyLimit
	ch <- c.forwarderCache
	ch <- c.forwarderInFlight
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
}
