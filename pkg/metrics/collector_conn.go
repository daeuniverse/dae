/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package metrics

import (
	"github.com/daeuniverse/dae/control"
	"github.com/prometheus/client_golang/prometheus"
)

type ConnCollector struct {
	state *State

	tcpConnectionsActive *prometheus.Desc
	udpEndpointsActive   *prometheus.Desc
	udpTaskQueuesActive  *prometheus.Desc
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
	}
}

func (c *ConnCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.tcpConnectionsActive
	ch <- c.udpEndpointsActive
	ch <- c.udpTaskQueuesActive
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
}
