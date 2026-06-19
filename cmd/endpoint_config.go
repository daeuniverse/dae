/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/metricshttp"
	"github.com/sirupsen/logrus"
)

func endpointConfigFromGlobal(conf *config.Config, log *logrus.Logger) metricshttp.EndpointConfig {
	cfg := metricshttp.EndpointConfig{
		ListenAddress:     conf.Global.EndpointListenAddress,
		Username:          conf.Global.EndpointUsername,
		Password:          conf.Global.EndpointPassword,
		TlsCertificate:    conf.Global.EndpointTlsCertificate,
		TlsKey:            conf.Global.EndpointTlsKey,
		PrometheusEnabled: conf.Global.EndpointPrometheusEnabled,
		PrometheusPath:    conf.Global.EndpointPrometheusPath,
		PprofEnabled:      conf.Global.PprofPort != 0,
	}
	if cfg.ListenAddress == "" && conf.Global.PprofPort != 0 {
		log.Warnln("pprof_port is deprecated, please use endpoint_listen_address instead")
		cfg.ListenAddress = fmt.Sprintf("localhost:%d", conf.Global.PprofPort)
	}
	return cfg
}

func endpointConfigChanged(a, b metricshttp.EndpointConfig) bool {
	return a != b
}

func validateEndpointTLSFiles(cfg metricshttp.EndpointConfig) error {
	if cfg.TlsCertificate == "" && cfg.TlsKey == "" {
		return nil
	}
	if cfg.TlsCertificate == "" || cfg.TlsKey == "" {
		return fmt.Errorf("endpoint_tls_certificate and endpoint_tls_key must be configured together")
	}

	certFile, err := os.Open(cfg.TlsCertificate)
	if err != nil {
		return fmt.Errorf("cannot open endpoint_tls_certificate '%s': %w", cfg.TlsCertificate, err)
	}
	defer func() { _ = certFile.Close() }()
	certFi, err := certFile.Stat()
	if err != nil {
		return fmt.Errorf("cannot stat endpoint_tls_certificate '%s': %w", cfg.TlsCertificate, err)
	}
	if err = common.ValidateFilePermissionAllowed(cfg.TlsCertificate, certFi, 0o640, 0o644); err != nil {
		return fmt.Errorf("invalid endpoint_tls_certificate: %w", err)
	}

	keyFile, err := os.Open(cfg.TlsKey)
	if err != nil {
		return fmt.Errorf("cannot open endpoint_tls_key '%s': %w", cfg.TlsKey, err)
	}
	defer func() { _ = keyFile.Close() }()
	keyFi, err := keyFile.Stat()
	if err != nil {
		return fmt.Errorf("cannot stat endpoint_tls_key '%s': %w", cfg.TlsKey, err)
	}
	if err = common.ValidateFilePermissionAllowed(cfg.TlsKey, keyFi, 0o600); err != nil {
		return fmt.Errorf("invalid endpoint_tls_key: %w", err)
	}
	return nil
}
