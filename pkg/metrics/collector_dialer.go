/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package metrics

import (
	"fmt"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/prometheus/client_golang/prometheus"
)

// dialerMetricNetworkTypes lists each distinct health collection once.
// tcp4(DNS)/tcp6(DNS) share the tcp4/tcp6 collection and alive set (see
// dialer.NewDialerContext and DialerGroup.buildSelectionState), so exporting
// them would duplicate the TCP series.
var dialerMetricNetworkTypes = func() (types [6]*dialer.NetworkType) {
	for i, key := range dialer.StandardHealthKeys() {
		types[i] = key.NetworkType()
	}
	return types
}()

// dialerMetricName keeps label sets unique when a group holds several nodes
// with the same name (common with multiple subscriptions): a duplicate label
// set fails the whole scrape.
func dialerMetricName(seen map[string]int, name string) string {
	seen[name]++
	if n := seen[name]; n > 1 {
		return fmt.Sprintf("%s #%d", name, n)
	}
	return name
}

type DialerCollector struct {
	state *State

	dialerAlive            *prometheus.Desc
	dialerLatencyLast      *prometheus.Desc
	dialerLatencyAvg10     *prometheus.Desc
	dialerLatencyMovingAvg *prometheus.Desc
	healthCheckTotal       *prometheus.Desc
	healthCheckFailure     *prometheus.Desc
	groupAliveDialers      *prometheus.Desc
}

func NewDialerCollector(state *State) *DialerCollector {
	return &DialerCollector{
		state: state,
		dialerAlive: prometheus.NewDesc(
			"dae_dialer_alive",
			"Whether the dialer is alive (1 = alive, 0 = dead)",
			[]string{"group", "dialer", "network"},
			nil,
		),
		dialerLatencyLast: prometheus.NewDesc(
			"dae_dialer_latency_last_seconds",
			"Latency of the most recent successful health check in seconds; not emitted when last probe timed out",
			[]string{"group", "dialer", "network"},
			nil,
		),
		dialerLatencyAvg10: prometheus.NewDesc(
			"dae_dialer_latency_avg10_seconds",
			"The average latency of the last 10 health checks in seconds",
			[]string{"group", "dialer", "network"},
			nil,
		),
		dialerLatencyMovingAvg: prometheus.NewDesc(
			"dae_dialer_latency_moving_avg_seconds",
			"The exponentially weighted moving average latency in seconds",
			[]string{"group", "dialer", "network"},
			nil,
		),
		healthCheckTotal: prometheus.NewDesc(
			"dae_health_check_total",
			"Total number of dialer connectivity health checks that produced a verdict (success or failure)",
			[]string{"group", "dialer", "network"},
			nil,
		),
		healthCheckFailure: prometheus.NewDesc(
			"dae_health_check_failure_total",
			"Total number of failed dialer connectivity health checks",
			[]string{"group", "dialer", "network"},
			nil,
		),
		groupAliveDialers: prometheus.NewDesc(
			"dae_group_alive_dialers_total",
			"The number of currently alive dialers in the group",
			[]string{"group", "network"},
			nil,
		),
	}
}

func (c *DialerCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.dialerAlive
	ch <- c.dialerLatencyLast
	ch <- c.dialerLatencyAvg10
	ch <- c.dialerLatencyMovingAvg
	ch <- c.healthCheckTotal
	ch <- c.healthCheckFailure
	ch <- c.groupAliveDialers
}

func (c *DialerCollector) Collect(ch chan<- prometheus.Metric) {
	if c.state == nil {
		return
	}
	cp := c.state.GetControlPlane()
	if cp == nil {
		return
	}
	for _, group := range cp.Outbounds() {
		if group == nil {
			continue
		}
		seen := make(map[string]int, len(group.Dialers))
		for _, d := range group.Dialers {
			if d == nil {
				continue
			}
			prop := d.Property()
			if prop == nil {
				continue
			}
			name := dialerMetricName(seen, prop.Name)
			for _, typ := range dialerMetricNetworkTypes {
				alive, lastLatency, avg10, movingAvg, hasLastLatency := d.GetCollectionState(typ)
				aliveFloat := 0.0
				if alive {
					aliveFloat = 1
				}
				labels := []string{group.Name, name, typ.String()}
				ch <- prometheus.MustNewConstMetric(c.dialerAlive, prometheus.GaugeValue, aliveFloat, labels...)
				if hasLastLatency {
					ch <- prometheus.MustNewConstMetric(c.dialerLatencyLast, prometheus.GaugeValue, lastLatency.Seconds(), labels...)
				}
				ch <- prometheus.MustNewConstMetric(c.dialerLatencyAvg10, prometheus.GaugeValue, avg10.Seconds(), labels...)
				ch <- prometheus.MustNewConstMetric(c.dialerLatencyMovingAvg, prometheus.GaugeValue, movingAvg.Seconds(), labels...)
				checkTotal, checkFailureTotal := d.GetCollectionCounters(typ)
				ch <- prometheus.MustNewConstMetric(c.healthCheckTotal, prometheus.CounterValue, float64(checkTotal), labels...)
				ch <- prometheus.MustNewConstMetric(c.healthCheckFailure, prometheus.CounterValue, float64(checkFailureTotal), labels...)
			}
		}
		for _, typ := range dialerMetricNetworkTypes {
			set := group.MustGetAliveDialerSet(typ)
			if set == nil {
				continue
			}
			ch <- prometheus.MustNewConstMetric(
				c.groupAliveDialers,
				prometheus.GaugeValue,
				float64(set.Len()),
				group.Name,
				typ.String(),
			)
		}
	}
}
