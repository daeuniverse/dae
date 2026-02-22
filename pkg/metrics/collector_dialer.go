/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package metrics

import (
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/prometheus/client_golang/prometheus"
)

var dialerMetricNetworkTypes = [6]dialer.NetworkType{
	{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4, IsDns: true},
	{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_6, IsDns: true},
	{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, IsDns: true},
	{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_6, IsDns: true},
	{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4, IsDns: false},
	{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_6, IsDns: false},
}

type DialerCollector struct {
	state *State

	dialerAlive            *prometheus.Desc
	dialerLatencyLast      *prometheus.Desc
	dialerLatencyAvg10     *prometheus.Desc
	dialerLatencyMovingAvg *prometheus.Desc
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
			"The most recent health check latency in seconds",
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
		for _, d := range group.Dialers {
			if d == nil {
				continue
			}
			prop := d.Property()
			if prop == nil {
				continue
			}
			for i := range dialerMetricNetworkTypes {
				typ := dialerMetricNetworkTypes[i]
				alive, lastLatency, avg10, movingAvg := d.GetCollectionState(&typ)
				aliveFloat := 0.0
				if alive {
					aliveFloat = 1
				}
				labels := []string{group.Name, prop.Name, typ.String()}
				ch <- prometheus.MustNewConstMetric(c.dialerAlive, prometheus.GaugeValue, aliveFloat, labels...)
				ch <- prometheus.MustNewConstMetric(c.dialerLatencyLast, prometheus.GaugeValue, lastLatency.Seconds(), labels...)
				ch <- prometheus.MustNewConstMetric(c.dialerLatencyAvg10, prometheus.GaugeValue, avg10.Seconds(), labels...)
				ch <- prometheus.MustNewConstMetric(c.dialerLatencyMovingAvg, prometheus.GaugeValue, movingAvg.Seconds(), labels...)
			}
		}
		for i, set := range group.AliveDialerSets() {
			if set == nil {
				continue
			}
			ch <- prometheus.MustNewConstMetric(
				c.groupAliveDialers,
				prometheus.GaugeValue,
				float64(set.AliveCount()),
				group.Name,
				dialerMetricNetworkTypes[i].String(),
			)
		}
	}
}
