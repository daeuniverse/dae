/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package metrics

import (
	"github.com/daeuniverse/dae/control"
	"github.com/prometheus/client_golang/prometheus"
)

type RuntimeCollector struct {
	uploadBytesTotal   *prometheus.Desc
	downloadBytesTotal *prometheus.Desc
	uploadRate         *prometheus.Desc
	downloadRate       *prometheus.Desc
}

func NewRuntimeCollector() *RuntimeCollector {
	return &RuntimeCollector{
		uploadBytesTotal: prometheus.NewDesc(
			"dae_runtime_upload_bytes_total",
			"Total bytes proxied as upload traffic since process start",
			nil,
			nil,
		),
		downloadBytesTotal: prometheus.NewDesc(
			"dae_runtime_download_bytes_total",
			"Total bytes proxied as download traffic since process start",
			nil,
			nil,
		),
		uploadRate: prometheus.NewDesc(
			"dae_runtime_upload_rate_bytes_per_second",
			"Current upload traffic rate in bytes per second",
			nil,
			nil,
		),
		downloadRate: prometheus.NewDesc(
			"dae_runtime_download_rate_bytes_per_second",
			"Current download traffic rate in bytes per second",
			nil,
			nil,
		),
	}
}

func (c *RuntimeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.uploadBytesTotal
	ch <- c.downloadBytesTotal
	ch <- c.uploadRate
	ch <- c.downloadRate
}

func (c *RuntimeCollector) Collect(ch chan<- prometheus.Metric) {
	snap := control.SnapshotRuntimeStats(0, 0, 0, 0)
	ch <- prometheus.MustNewConstMetric(c.uploadBytesTotal, prometheus.CounterValue, float64(snap.UploadTotal))
	ch <- prometheus.MustNewConstMetric(c.downloadBytesTotal, prometheus.CounterValue, float64(snap.DownloadTotal))
	ch <- prometheus.MustNewConstMetric(c.uploadRate, prometheus.GaugeValue, float64(snap.UploadRate))
	ch <- prometheus.MustNewConstMetric(c.downloadRate, prometheus.GaugeValue, float64(snap.DownloadRate))
}
