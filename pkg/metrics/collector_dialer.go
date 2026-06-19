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

// dialerMetricNetworkTypes must be indexed by the Idx* constants in
// component/outbound/dialer (IdxDnsTcp4=0 … IdxUdp6=7) so that
// AliveDialerSets()[i] and dialerMetricNetworkTypes[i] stay in sync.
var dialerMetricNetworkTypes = [8]dialer.NetworkType{
	{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4, IsDns: true},                                             // [0] IdxDnsTcp4
	{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_6, IsDns: true},                                             // [1] IdxDnsTcp6
	{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, IsDns: true, UdpHealthDomain: dialer.UdpHealthDomainDns}, // [2] IdxDnsUdp4
	{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_6, IsDns: true, UdpHealthDomain: dialer.UdpHealthDomainDns}, // [3] IdxDnsUdp6
	{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4, IsDns: false},                                            // [4] IdxTcp4
	{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_6, IsDns: false},                                            // [5] IdxTcp6
	{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, IsDns: false},                                            // [6] IdxUdp4
	{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_6, IsDns: false},                                            // [7] IdxUdp6
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
			"Total number of dialer connectivity health checks",
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
				alive, lastLatency, avg10, movingAvg, hasLastLatency := d.GetCollectionState(&typ)
				aliveFloat := 0.0
				if alive {
					aliveFloat = 1
				}
				labels := []string{group.Name, prop.Name, typ.String()}
				ch <- prometheus.MustNewConstMetric(c.dialerAlive, prometheus.GaugeValue, aliveFloat, labels...)
				if hasLastLatency {
					ch <- prometheus.MustNewConstMetric(c.dialerLatencyLast, prometheus.GaugeValue, lastLatency.Seconds(), labels...)
				}
				ch <- prometheus.MustNewConstMetric(c.dialerLatencyAvg10, prometheus.GaugeValue, avg10.Seconds(), labels...)
				ch <- prometheus.MustNewConstMetric(c.dialerLatencyMovingAvg, prometheus.GaugeValue, movingAvg.Seconds(), labels...)
				checkTotal, checkFailureTotal := d.GetCollectionCounters(&typ)
				ch <- prometheus.MustNewConstMetric(c.healthCheckTotal, prometheus.CounterValue, float64(checkTotal), labels...)
				ch <- prometheus.MustNewConstMetric(c.healthCheckFailure, prometheus.CounterValue, float64(checkFailureTotal), labels...)
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
