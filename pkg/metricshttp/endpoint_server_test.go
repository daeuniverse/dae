/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package metricshttp

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func basicAuthValue(user, pass string) string {
	token := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	return "Basic " + token
}

func TestNormalizePrometheusPath(t *testing.T) {
	if got := NormalizePrometheusPath(""); got != "/metrics" {
		t.Fatalf("unexpected default path: got=%q want=%q", got, "/metrics")
	}
	if got := NormalizePrometheusPath("custom"); got != "/custom" {
		t.Fatalf("unexpected relative path normalization: got=%q want=%q", got, "/custom")
	}
	if got := NormalizePrometheusPath("/custom"); got != "/custom" {
		t.Fatalf("unexpected absolute path normalization: got=%q want=%q", got, "/custom")
	}
}

func TestBasicAuthMiddlewareRejectsMissingCredentials(t *testing.T) {
	handler := BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "dae", "secret")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected status without credentials: got=%d want=%d", rec.Code, http.StatusUnauthorized)
	}
}

func TestBasicAuthMiddlewareAllowsValidCredentials(t *testing.T) {
	handler := BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "dae", "secret")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", basicAuthValue("dae", "secret"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("unexpected status with valid credentials: got=%d want=%d", rec.Code, http.StatusNoContent)
	}
}

func TestNewEndpointServerServesPrometheusAndPprofWithAuth(t *testing.T) {
	reg := prometheus.NewRegistry()
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dae_test_metric_total",
		Help: "test metric",
	})
	reg.MustRegister(counter)
	counter.Inc()

	server := NewEndpointServer(EndpointConfig{
		ListenAddress:     "127.0.0.1:0",
		Username:          "dae",
		Password:          "secret",
		PrometheusEnabled: true,
		PrometheusPath:    "/custom-metrics",
		PprofEnabled:      true,
	}, reg)

	metricsReq := httptest.NewRequest(http.MethodGet, "/custom-metrics", nil)
	metricsReq.Header.Set("Authorization", basicAuthValue("dae", "secret"))
	metricsRec := httptest.NewRecorder()
	server.Handler.ServeHTTP(metricsRec, metricsReq)
	if metricsRec.Code != http.StatusOK {
		t.Fatalf("unexpected metrics status: got=%d want=%d", metricsRec.Code, http.StatusOK)
	}
	if body := metricsRec.Body.String(); !strings.Contains(body, "dae_test_metric_total") {
		t.Fatalf("expected Prometheus response body to contain test metric, got=%q", body)
	}

	pprofReq := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	pprofReq.Header.Set("Authorization", basicAuthValue("dae", "secret"))
	pprofRec := httptest.NewRecorder()
	server.Handler.ServeHTTP(pprofRec, pprofReq)
	if pprofRec.Code != http.StatusOK {
		t.Fatalf("unexpected pprof status: got=%d want=%d", pprofRec.Code, http.StatusOK)
	}
}

// dupCollector emits the same label set twice, as two same-named nodes in one
// group would.
type dupCollector struct{ desc *prometheus.Desc }

func (c dupCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }
func (c dupCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, 1, "dup")
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, 0, "dup")
}

func TestPrometheusHandlerSurvivesCollectorError(t *testing.T) {
	reg := prometheus.NewRegistry()
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dae_test_metric_total",
		Help: "test metric",
	})
	reg.MustRegister(counter, dupCollector{prometheus.NewDesc("dae_test_dup", "dup", []string{"name"}, nil)})

	server := NewEndpointServer(EndpointConfig{
		ListenAddress:     "127.0.0.1:0",
		PrometheusEnabled: true,
	}, reg)
	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("one bad collector must not fail the scrape: status=%d body=%q", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "dae_test_metric_total") {
		t.Fatalf("healthy metrics missing from body: %q", body)
	}
}
