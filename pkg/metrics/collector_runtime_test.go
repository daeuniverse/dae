/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package metrics

import (
	"math"
	"testing"

	"github.com/daeuniverse/dae/control"
	dto "github.com/prometheus/client_model/go"
)

func counterMetricValue(t *testing.T, family *dto.MetricFamily) float64 {
	t.Helper()
	if family == nil {
		t.Fatal("metric family is nil")
	}
	if len(family.Metric) != 1 || family.Metric[0].Counter == nil {
		t.Fatalf("expected single counter metric in %q", family.GetName())
	}
	return family.Metric[0].Counter.GetValue()
}

func gaugeMetricValue(t *testing.T, family *dto.MetricFamily) float64 {
	t.Helper()
	if family == nil {
		t.Fatal("metric family is nil")
	}
	if len(family.Metric) != 1 || family.Metric[0].Gauge == nil {
		t.Fatalf("expected single gauge metric in %q", family.GetName())
	}
	return family.Metric[0].Gauge.GetValue()
}

func TestRegistryGatherReportsRuntimeTrafficMetrics(t *testing.T) {
	reg := NewRegistry(nil)

	before, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather metrics before traffic: %v", err)
	}
	beforeUpload := counterMetricValue(t, metricFamilyByName(before, "dae_runtime_upload_bytes_total"))
	beforeDownload := counterMetricValue(t, metricFamilyByName(before, "dae_runtime_download_bytes_total"))

	control.RecordUploadTraffic(1234)
	control.RecordDownloadTraffic(2345)

	after, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather metrics after traffic: %v", err)
	}

	afterUpload := counterMetricValue(t, metricFamilyByName(after, "dae_runtime_upload_bytes_total"))
	afterDownload := counterMetricValue(t, metricFamilyByName(after, "dae_runtime_download_bytes_total"))
	if afterUpload-beforeUpload < 1234 {
		t.Fatalf("upload counter delta = %v, want >= 1234", afterUpload-beforeUpload)
	}
	if afterDownload-beforeDownload < 2345 {
		t.Fatalf("download counter delta = %v, want >= 2345", afterDownload-beforeDownload)
	}

	uploadRate := gaugeMetricValue(t, metricFamilyByName(after, "dae_runtime_upload_rate_bytes_per_second"))
	downloadRate := gaugeMetricValue(t, metricFamilyByName(after, "dae_runtime_download_rate_bytes_per_second"))
	if uploadRate < 0 || math.IsNaN(uploadRate) || math.IsInf(uploadRate, 0) {
		t.Fatalf("upload rate = %v, want finite non-negative", uploadRate)
	}
	if downloadRate < 0 || math.IsNaN(downloadRate) || math.IsInf(downloadRate, 0) {
		t.Fatalf("download rate = %v, want finite non-negative", downloadRate)
	}
}
