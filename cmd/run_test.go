/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/metricshttp"
	"github.com/sirupsen/logrus"
)

func writeEndpointFile(t *testing.T, name string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write endpoint file: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod endpoint file: %v", err)
	}
	return path
}

func TestEndpointConfigFromGlobalUsesEndpointSettings(t *testing.T) {
	conf := &config.Config{}
	conf.Global.EndpointListenAddress = "127.0.0.1:5556"
	conf.Global.EndpointUsername = "dae"
	conf.Global.EndpointPassword = "secret"
	conf.Global.EndpointTlsCertificate = "/tmp/cert.pem"
	conf.Global.EndpointTlsKey = "/tmp/key.pem"
	conf.Global.EndpointPrometheusEnabled = true
	conf.Global.EndpointPrometheusPath = "/custom-metrics"
	conf.Global.PprofPort = 0

	cfg := endpointConfigFromGlobal(conf, logrus.New())
	if cfg.ListenAddress != "127.0.0.1:5556" {
		t.Fatalf("unexpected listen address: got=%q", cfg.ListenAddress)
	}
	if cfg.Username != "dae" || cfg.Password != "secret" {
		t.Fatalf("unexpected credentials: got=%q/%q", cfg.Username, cfg.Password)
	}
	if !cfg.PrometheusEnabled || cfg.PrometheusPath != "/custom-metrics" {
		t.Fatalf("unexpected prometheus settings: enabled=%v path=%q", cfg.PrometheusEnabled, cfg.PrometheusPath)
	}
	if cfg.PprofEnabled {
		t.Fatal("pprof should be disabled when pprof_port is zero")
	}
}

func TestEndpointConfigFromGlobalFallsBackToPprofPort(t *testing.T) {
	conf := &config.Config{}
	conf.Global.PprofPort = 6060

	cfg := endpointConfigFromGlobal(conf, logrus.New())
	if cfg.ListenAddress != "localhost:6060" {
		t.Fatalf("unexpected pprof fallback address: got=%q want=%q", cfg.ListenAddress, "localhost:6060")
	}
	if !cfg.PprofEnabled {
		t.Fatal("pprof should be enabled when pprof_port is non-zero")
	}
}

func TestValidateEndpointTLSFilesRequiresPair(t *testing.T) {
	err := validateEndpointTLSFiles(endpointConfigFromGlobal(&config.Config{}, logrus.New()))
	if err != nil {
		t.Fatalf("empty endpoint tls config should pass: %v", err)
	}

	err = validateEndpointTLSFiles(metricshttp.EndpointConfig{
		TlsCertificate: "/tmp/cert.pem",
	})
	if err == nil {
		t.Fatal("expected certificate-only config to fail")
	}
}

func TestValidateEndpointTLSFilesChecksPermissions(t *testing.T) {
	cert := writeEndpointFile(t, "cert.pem", 0o640)
	key := writeEndpointFile(t, "key.pem", 0o600)

	if err := validateEndpointTLSFiles(metricshttp.EndpointConfig{
		TlsCertificate: cert,
		TlsKey:         key,
	}); err != nil {
		t.Fatalf("expected valid certificate/key permissions to pass: %v", err)
	}

	tooOpenCert := writeEndpointFile(t, "cert-open.pem", 0o666)
	err := validateEndpointTLSFiles(metricshttp.EndpointConfig{
		TlsCertificate: tooOpenCert,
		TlsKey:         key,
	})
	if err == nil {
		t.Fatal("expected too-open certificate permissions to fail")
	}
}
