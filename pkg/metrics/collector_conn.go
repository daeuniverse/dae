/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package metrics

import (
	"sort"

	"github.com/daeuniverse/dae/control"
	"github.com/prometheus/client_golang/prometheus"
)

type ConnCollector struct {
	state *State

	tcpConnectionsActive *prometheus.Desc
	udpEndpointsActive   *prometheus.Desc
	udpTaskQueuesActive  *prometheus.Desc
	tcpConnectionsTotal  *prometheus.Desc
	udpConnectionsTotal  *prometheus.Desc
}

func NewConnCollector(state *State) *ConnCollector {
	return &ConnCollector{
		state: state,
		tcpConnectionsActive: prometheus.NewDesc(
			"dae_tcp_connections_active",
			"The number of currently active TCP connections being proxied",
			nil,
			nil,
		),
		udpEndpointsActive: prometheus.NewDesc(
			"dae_udp_endpoints_active",
			"The number of currently active UDP endpoint associations",
			nil,
			nil,
		),
		udpTaskQueuesActive: prometheus.NewDesc(
			"dae_udp_task_queues_active",
			"The number of currently active UDP task queues",
			nil,
			nil,
		),
		tcpConnectionsTotal: prometheus.NewDesc(
			"dae_tcp_connections_total",
			"Total number of successfully established proxied TCP connections",
			[]string{"protocol", "group"},
			nil,
		),
		udpConnectionsTotal: prometheus.NewDesc(
			"dae_udp_connections_total",
			"Total number of new proxied UDP endpoint associations with successful first packet",
			[]string{"protocol", "group"},
			nil,
		),
	}
}

func (c *ConnCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.tcpConnectionsActive
	ch <- c.udpEndpointsActive
	ch <- c.udpTaskQueuesActive
	ch <- c.tcpConnectionsTotal
	ch <- c.udpConnectionsTotal
}

func (c *ConnCollector) Collect(ch chan<- prometheus.Metric) {
	if c.state == nil {
		return
	}
	cp := c.state.GetControlPlane()
	if cp == nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.tcpConnectionsActive, prometheus.GaugeValue, float64(cp.CountTcpConnections()))
	ch <- prometheus.MustNewConstMetric(c.udpEndpointsActive, prometheus.GaugeValue, float64(control.DefaultUdpEndpointPool.Count()))
	ch <- prometheus.MustNewConstMetric(c.udpTaskQueuesActive, prometheus.GaugeValue, float64(control.DefaultUdpTaskPool.Count()))

	tcpSnapshot := cp.TcpConnectionTotalsSnapshot()
	tcpKeys := make([]control.ConnMetricKey, 0, len(tcpSnapshot))
	for key := range tcpSnapshot {
		tcpKeys = append(tcpKeys, key)
	}
	sort.Slice(tcpKeys, func(i, j int) bool {
		if tcpKeys[i].Protocol == tcpKeys[j].Protocol {
			return tcpKeys[i].Group < tcpKeys[j].Group
		}
		return tcpKeys[i].Protocol < tcpKeys[j].Protocol
	})
	for _, key := range tcpKeys {
		ch <- prometheus.MustNewConstMetric(
			c.tcpConnectionsTotal,
			prometheus.CounterValue,
			float64(tcpSnapshot[key]),
			key.Protocol,
			key.Group,
		)
	}

	udpSnapshot := cp.UdpConnectionTotalsSnapshot()
	udpKeys := make([]control.ConnMetricKey, 0, len(udpSnapshot))
	for key := range udpSnapshot {
		udpKeys = append(udpKeys, key)
	}
	sort.Slice(udpKeys, func(i, j int) bool {
		if udpKeys[i].Protocol == udpKeys[j].Protocol {
			return udpKeys[i].Group < udpKeys[j].Group
		}
		return udpKeys[i].Protocol < udpKeys[j].Protocol
	})
	for _, key := range udpKeys {
		ch <- prometheus.MustNewConstMetric(
			c.udpConnectionsTotal,
			prometheus.CounterValue,
			float64(udpSnapshot[key]),
			key.Protocol,
			key.Group,
		)
	}
}
