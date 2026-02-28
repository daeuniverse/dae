/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package metrics

import (
	"net/http"
	"net/http/pprof"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type EndpointConfig struct {
	ListenAddress     string
	Username          string
	Password          string
	TlsCertificate    string
	TlsKey            string
	PrometheusEnabled bool
	PrometheusPath    string
	PprofEnabled      bool
}

func normalizePrometheusPath(path string) string {
	if path == "" {
		return "/metrics"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func NewEndpointServer(cfg EndpointConfig, registry *prometheus.Registry) *http.Server {
	mux := http.NewServeMux()
	if cfg.PrometheusEnabled && registry != nil {
		mux.Handle(normalizePrometheusPath(cfg.PrometheusPath),
			BasicAuthMiddleware(
				promhttp.HandlerFor(registry, promhttp.HandlerOpts{}),
				cfg.Username, cfg.Password,
			),
		)
	}
	if cfg.PprofEnabled {
		mux.Handle("/debug/pprof/", BasicAuthMiddleware(http.HandlerFunc(pprof.Index), cfg.Username, cfg.Password))
		mux.Handle("/debug/pprof/cmdline", BasicAuthMiddleware(http.HandlerFunc(pprof.Cmdline), cfg.Username, cfg.Password))
		mux.Handle("/debug/pprof/profile", BasicAuthMiddleware(http.HandlerFunc(pprof.Profile), cfg.Username, cfg.Password))
		mux.Handle("/debug/pprof/symbol", BasicAuthMiddleware(http.HandlerFunc(pprof.Symbol), cfg.Username, cfg.Password))
		mux.Handle("/debug/pprof/trace", BasicAuthMiddleware(http.HandlerFunc(pprof.Trace), cfg.Username, cfg.Password))
	}
	return &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

func StartEndpointServer(server *http.Server, cfg EndpointConfig) error {
	if server == nil {
		return nil
	}
	if cfg.TlsCertificate != "" && cfg.TlsKey != "" {
		return server.ListenAndServeTLS(cfg.TlsCertificate, cfg.TlsKey)
	}
	return server.ListenAndServe()
}
