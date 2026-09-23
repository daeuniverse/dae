/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/metricshttp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

// managementPlan is the pure decision for which management listeners a config
// needs. It does not bind sockets.
type managementPlan struct {
	endpointCfg   metricshttp.EndpointConfig
	separatePprof bool
	pprofAddr     string
}

// resolveManagementServers decides the endpoint config and whether a separate
// pprof server is required.
//
// An empty endpoint_listen_address with a non-zero pprof_port falls back to
// localhost:<pprof_port> on the endpoint mux and does not start a second
// server. An explicit address equal to that fallback is a configuration error.
// A different explicit address keeps upstream's separate pprof server.
func resolveManagementServers(conf *config.Config, log *logrus.Logger) (managementPlan, error) {
	if conf == nil {
		return managementPlan{}, nil
	}
	if log == nil {
		log = logrus.New()
		log.SetOutput(io.Discard)
	}

	pprofPort := conf.Global.PprofPort
	explicit := conf.Global.EndpointListenAddress
	var pprofAddr string
	if pprofPort != 0 {
		pprofAddr = fmt.Sprintf("localhost:%d", pprofPort)
	}
	if explicit != "" && pprofPort != 0 && explicit == pprofAddr {
		return managementPlan{}, fmt.Errorf("endpoint_listen_address %q equals the pprof_port %d listen address %s; leave endpoint_listen_address empty to share one server, or set a different address", explicit, pprofPort, pprofAddr)
	}

	cfg := endpointConfigFromGlobal(conf, log)
	if err := validateEndpointTLSFiles(cfg); err != nil {
		return managementPlan{}, fmt.Errorf("invalid endpoint tls config: %w", err)
	}

	plan := managementPlan{endpointCfg: cfg}
	if explicit != "" && pprofPort != 0 {
		plan.separatePprof = true
		plan.pprofAddr = pprofAddr
	}
	return plan, nil
}

// managementServers owns the endpoint HTTP server and, when the endpoint
// address is not the pprof fallback, the separate pprof server. Run's
// goroutine is the only caller of start, apply, and shutdown.
type managementServers struct {
	log            *logrus.Logger
	registry       *prometheus.Registry
	endpointCfg    metricshttp.EndpointConfig
	endpointServer *http.Server
	pprofServer    *http.Server
}

func (m *managementServers) start(conf *config.Config) error {
	if m == nil {
		return nil
	}
	plan, err := resolveManagementServers(conf, m.log)
	if err != nil {
		return err
	}
	if plan.endpointCfg.ListenAddress != "" {
		m.startEndpoint(plan.endpointCfg)
	} else {
		m.endpointCfg = plan.endpointCfg
	}
	if plan.separatePprof {
		m.startPprof(plan.pprofAddr)
	}
	return nil
}

// apply rebinds listeners whose config changed. Servers that changed are shut
// down before any new listener is started, so a fallback port can be handed
// from the endpoint server to the separate pprof server (and the reverse).
// An unchanged endpoint config leaves the endpoint *http.Server in place.
func (m *managementServers) apply(newConf *config.Config) {
	if m == nil {
		return
	}
	plan, err := resolveManagementServers(newConf, m.log)
	if err != nil {
		if m.log != nil {
			m.log.WithError(err).Errorln("Management server config rejected; leaving servers unchanged")
		}
		return
	}

	wantEndpoint := plan.endpointCfg.ListenAddress != ""
	restartEndpoint := (!wantEndpoint && m.endpointServer != nil) ||
		(wantEndpoint && (m.endpointServer == nil || endpointConfigChanged(m.endpointCfg, plan.endpointCfg)))
	wantPprof := plan.separatePprof
	restartPprof := (!wantPprof && m.pprofServer != nil) ||
		(wantPprof && (m.pprofServer == nil || m.pprofServer.Addr != plan.pprofAddr))
	if !restartEndpoint && !restartPprof {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if restartEndpoint && m.endpointServer != nil {
		_ = m.endpointServer.Shutdown(ctx)
		m.endpointServer = nil
	}
	if restartPprof && m.pprofServer != nil {
		_ = m.pprofServer.Shutdown(ctx)
		m.pprofServer = nil
	}
	if restartEndpoint {
		if wantEndpoint {
			m.startEndpoint(plan.endpointCfg)
		} else {
			m.endpointCfg = plan.endpointCfg
		}
	}
	if restartPprof && wantPprof {
		m.startPprof(plan.pprofAddr)
	}
}

func (m *managementServers) shutdown(ctx context.Context) {
	if m == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if m.endpointServer != nil {
		if m.log != nil {
			m.log.Infoln("Shutting down endpoint server")
		}
		_ = m.endpointServer.Shutdown(ctx)
		m.endpointServer = nil
	}
	if m.pprofServer != nil {
		if m.log != nil {
			m.log.Infoln("Shutting down pprof server")
		}
		_ = m.pprofServer.Shutdown(ctx)
		m.pprofServer = nil
	}
}

func (m *managementServers) startEndpoint(cfg metricshttp.EndpointConfig) {
	m.endpointCfg = cfg
	if cfg.ListenAddress == "" {
		m.endpointServer = nil
		return
	}
	server := metricshttp.NewEndpointServer(cfg, m.registry)
	m.endpointServer = server
	log := m.log
	go func() {
		err := metricshttp.StartEndpointServer(server, cfg)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && log != nil {
			log.WithError(err).Errorln("Endpoint server stopped with error")
		}
	}()
}

func (m *managementServers) startPprof(addr string) {
	server := &http.Server{Addr: addr, Handler: nil}
	m.pprofServer = server
	log := m.log
	go func() {
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) && log != nil {
			log.WithError(err).Errorln("pprof server stopped with error")
		}
	}()
}
