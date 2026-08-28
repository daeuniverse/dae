/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

type RuntimeCollector struct {
	state *State

	uploadBytesTotal           *prometheus.Desc
	downloadBytesTotal         *prometheus.Desc
	uploadRateBytesPerSecond   *prometheus.Desc
	downloadRateBytesPerSecond *prometheus.Desc
	nodeLatencySeconds         *prometheus.Desc
	nodeAlive                  *prometheus.Desc
}

func NewRuntimeCollector(state *State) *RuntimeCollector {
	return &RuntimeCollector{
		state: state,
		uploadBytesTotal: prometheus.NewDesc(
			"dae_runtime_upload_bytes_total",
			"Total uploaded bytes observed by runtime traffic statistics",
			nil,
			nil,
		),
		downloadBytesTotal: prometheus.NewDesc(
			"dae_runtime_download_bytes_total",
			"Total downloaded bytes observed by runtime traffic statistics",
			nil,
			nil,
		),
		uploadRateBytesPerSecond: prometheus.NewDesc(
			"dae_runtime_upload_rate_bytes_per_second",
			"Current upload throughput observed by runtime traffic statistics",
			nil,
			nil,
		),
		downloadRateBytesPerSecond: prometheus.NewDesc(
			"dae_runtime_download_rate_bytes_per_second",
			"Current download throughput observed by runtime traffic statistics",
			nil,
			nil,
		),
		nodeLatencySeconds: prometheus.NewDesc(
			"dae_node_latency_seconds",
			"Best known per-node latency snapshot exported from runtime latency probing",
			[]string{"group", "name", "link"},
			nil,
		),
		nodeAlive: prometheus.NewDesc(
			"dae_node_alive",
			"Whether the node is currently considered alive by runtime latency probing",
			[]string{"group", "name", "link"},
			nil,
		),
	}
}

func (c *RuntimeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.uploadBytesTotal
	ch <- c.downloadBytesTotal
	ch <- c.uploadRateBytesPerSecond
	ch <- c.downloadRateBytesPerSecond
	ch <- c.nodeLatencySeconds
	ch <- c.nodeAlive
}

func (c *RuntimeCollector) Collect(ch chan<- prometheus.Metric) {
	if c.state == nil {
		return
	}
	cp := c.state.GetControlPlane()
	if cp == nil {
		return
	}

	snapshot := cp.SnapshotRuntimeStats(0, 0)
	ch <- prometheus.MustNewConstMetric(c.uploadBytesTotal, prometheus.CounterValue, float64(snapshot.UploadTotal))
	ch <- prometheus.MustNewConstMetric(c.downloadBytesTotal, prometheus.CounterValue, float64(snapshot.DownloadTotal))
	ch <- prometheus.MustNewConstMetric(c.uploadRateBytesPerSecond, prometheus.GaugeValue, float64(snapshot.UploadRate))
	ch <- prometheus.MustNewConstMetric(c.downloadRateBytesPerSecond, prometheus.GaugeValue, float64(snapshot.DownloadRate))

	for _, node := range cp.SnapshotNodeLatencies() {
		if node.Link == "" {
			continue
		}
		alive := 0.0
		if node.Alive {
			alive = 1
		}
		ch <- prometheus.MustNewConstMetric(c.nodeAlive, prometheus.GaugeValue, alive, node.Group, node.Name, node.Link)
		if node.LatencyMs != nil {
			ch <- prometheus.MustNewConstMetric(c.nodeLatencySeconds, prometheus.GaugeValue, float64(*node.LatencyMs)/1000.0, node.Group, node.Name, node.Link)
		}
	}
}
