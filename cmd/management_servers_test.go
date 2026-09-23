/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/metrics"
	"github.com/sirupsen/logrus"
)

func testManagementLog() *logrus.Logger {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return log
}

func TestResolveManagementServers(t *testing.T) {
	log := testManagementLog()

	t.Run("fallback shares endpoint and disables separate pprof", func(t *testing.T) {
		conf := &config.Config{}
		conf.Global.PprofPort = 6060
		plan, err := resolveManagementServers(conf, log)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if plan.separatePprof || plan.pprofAddr != "" {
			t.Fatalf("separate pprof = %v addr %q, want none", plan.separatePprof, plan.pprofAddr)
		}
		if plan.endpointCfg.ListenAddress != "localhost:6060" {
			t.Fatalf("listen = %q, want localhost:6060", plan.endpointCfg.ListenAddress)
		}
		if !plan.endpointCfg.PprofEnabled {
			t.Fatal("fallback endpoint must serve /debug/pprof/")
		}
	})

	t.Run("explicit different address keeps two servers", func(t *testing.T) {
		conf := &config.Config{}
		conf.Global.EndpointListenAddress = "127.0.0.1:5556"
		conf.Global.PprofPort = 6060
		plan, err := resolveManagementServers(conf, log)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if !plan.separatePprof || plan.pprofAddr != "localhost:6060" {
			t.Fatalf("separate pprof = %v addr %q, want localhost:6060", plan.separatePprof, plan.pprofAddr)
		}
		if plan.endpointCfg.ListenAddress != "127.0.0.1:5556" {
			t.Fatalf("listen = %q, want explicit address", plan.endpointCfg.ListenAddress)
		}
		if plan.endpointCfg.PprofEnabled {
			t.Fatal("explicit endpoint address must not also mount /debug/pprof/")
		}
	})

	t.Run("numeric loopback is not the localhost fallback address", func(t *testing.T) {
		conf := &config.Config{}
		conf.Global.EndpointListenAddress = "127.0.0.1:6060"
		conf.Global.PprofPort = 6060
		plan, err := resolveManagementServers(conf, log)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if !plan.separatePprof || plan.pprofAddr != "localhost:6060" {
			t.Fatalf("separate pprof = %v addr %q", plan.separatePprof, plan.pprofAddr)
		}
	})

	t.Run("explicit address equal to pprof fallback is a configuration error", func(t *testing.T) {
		conf := &config.Config{}
		conf.Global.EndpointListenAddress = "localhost:6060"
		conf.Global.PprofPort = 6060
		_, err := resolveManagementServers(conf, log)
		if err == nil {
			t.Fatal("expected collision error")
		}
		msg := err.Error()
		if !strings.Contains(msg, "endpoint_listen_address") || !strings.Contains(msg, "pprof_port") {
			t.Fatalf("error should name both keys, got %q", msg)
		}
	})

	t.Run("nothing configured starts nothing", func(t *testing.T) {
		plan, err := resolveManagementServers(&config.Config{}, log)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if plan.separatePprof || plan.pprofAddr != "" || plan.endpointCfg.ListenAddress != "" || plan.endpointCfg.PprofEnabled {
			t.Fatalf("zero config plan = %+v", plan)
		}
		plan, err = resolveManagementServers(nil, log)
		if err != nil {
			t.Fatalf("nil config: %v", err)
		}
		if plan.separatePprof || plan.endpointCfg.ListenAddress != "" {
			t.Fatalf("nil config plan = %+v", plan)
		}
	})

	t.Run("endpoint without pprof does not start a pprof server", func(t *testing.T) {
		conf := &config.Config{}
		conf.Global.EndpointListenAddress = "127.0.0.1:5556"
		plan, err := resolveManagementServers(conf, log)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if plan.separatePprof || plan.pprofAddr != "" {
			t.Fatalf("separate pprof = %v addr %q", plan.separatePprof, plan.pprofAddr)
		}
		if plan.endpointCfg.ListenAddress != "127.0.0.1:5556" || plan.endpointCfg.PprofEnabled {
			t.Fatalf("endpoint plan = %+v", plan.endpointCfg)
		}
	})

	t.Run("tls validation error", func(t *testing.T) {
		conf := &config.Config{}
		conf.Global.EndpointListenAddress = "127.0.0.1:5556"
		conf.Global.EndpointTlsCertificate = "/no/such/endpoint-cert.pem"
		conf.Global.EndpointTlsKey = "/no/such/endpoint-key.pem"
		_, err := resolveManagementServers(conf, log)
		if err == nil {
			t.Fatal("expected tls validation error")
		}
	})
}

func freeLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen :0: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close :0: %v", err)
	}
	return port
}

func waitForHTTPStatus(t *testing.T, url string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == want {
				return
			}
			last = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			last = err
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("GET %s: %v", url, last)
}

func waitForHTTPDown(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("GET %s still served", url)
}

func newTestManagementServers(t *testing.T) *managementServers {
	t.Helper()
	state := metrics.NewState()
	return &managementServers{
		log:      testManagementLog(),
		registry: metrics.NewRegistry(state),
	}
}

func TestManagementServersFallbackSharesOnePort(t *testing.T) {
	port := freeLocalPort(t)
	conf := &config.Config{}
	conf.Global.PprofPort = uint16(port)
	conf.Global.EndpointPrometheusEnabled = true

	m := newTestManagementServers(t)
	if err := m.start(conf); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { m.shutdown(context.Background()) })
	if m.pprofServer != nil {
		t.Fatal("fallback must not start a separate pprof server")
	}
	base := fmt.Sprintf("http://localhost:%d", port)
	waitForHTTPStatus(t, base+"/debug/pprof/", http.StatusOK)
	waitForHTTPStatus(t, base+"/metrics", http.StatusOK)
}

func TestManagementServersApplyRebindsChangedAddress(t *testing.T) {
	port1 := freeLocalPort(t)
	port2 := freeLocalPort(t)
	conf := &config.Config{}
	conf.Global.EndpointListenAddress = fmt.Sprintf("127.0.0.1:%d", port1)
	conf.Global.EndpointPrometheusEnabled = true

	m := newTestManagementServers(t)
	if err := m.start(conf); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { m.shutdown(context.Background()) })
	waitForHTTPStatus(t, fmt.Sprintf("http://127.0.0.1:%d/metrics", port1), http.StatusOK)
	first := m.endpointServer

	next := &config.Config{}
	next.Global.EndpointListenAddress = fmt.Sprintf("127.0.0.1:%d", port2)
	next.Global.EndpointPrometheusEnabled = true
	m.apply(next)
	if m.endpointServer == nil || m.endpointServer == first {
		t.Fatal("changed address must replace the endpoint server")
	}
	waitForHTTPDown(t, fmt.Sprintf("http://127.0.0.1:%d/metrics", port1))
	waitForHTTPStatus(t, fmt.Sprintf("http://127.0.0.1:%d/metrics", port2), http.StatusOK)
}

func TestManagementServersApplyUnchangedKeepsServer(t *testing.T) {
	port := freeLocalPort(t)
	conf := &config.Config{}
	conf.Global.EndpointListenAddress = fmt.Sprintf("127.0.0.1:%d", port)
	conf.Global.EndpointPrometheusEnabled = true

	m := newTestManagementServers(t)
	if err := m.start(conf); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { m.shutdown(context.Background()) })
	first := m.endpointServer
	if first == nil {
		t.Fatal("expected endpoint server")
	}
	m.apply(conf)
	if m.endpointServer != first {
		t.Fatal("unchanged config must keep the same endpoint server")
	}
}

func TestManagementServersFallbackToSeparatePprof(t *testing.T) {
	pprofPort := freeLocalPort(t)
	endpointPort := freeLocalPort(t)
	conf := &config.Config{}
	conf.Global.PprofPort = uint16(pprofPort)
	conf.Global.EndpointPrometheusEnabled = true

	m := newTestManagementServers(t)
	if err := m.start(conf); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { m.shutdown(context.Background()) })
	if m.pprofServer != nil {
		t.Fatal("fallback must not start a separate pprof server")
	}
	waitForHTTPStatus(t, fmt.Sprintf("http://localhost:%d/metrics", pprofPort), http.StatusOK)

	next := &config.Config{}
	next.Global.EndpointListenAddress = fmt.Sprintf("127.0.0.1:%d", endpointPort)
	next.Global.PprofPort = uint16(pprofPort)
	next.Global.EndpointPrometheusEnabled = true
	m.apply(next)
	if m.pprofServer == nil || m.pprofServer.Addr != fmt.Sprintf("localhost:%d", pprofPort) {
		t.Fatalf("separate pprof = %#v", m.pprofServer)
	}
	if m.endpointServer == nil || m.endpointServer.Addr != next.Global.EndpointListenAddress {
		t.Fatalf("endpoint = %#v", m.endpointServer)
	}
	waitForHTTPStatus(t, fmt.Sprintf("http://127.0.0.1:%d/metrics", endpointPort), http.StatusOK)
	waitForHTTPStatus(t, fmt.Sprintf("http://localhost:%d/debug/pprof/", pprofPort), http.StatusOK)
	waitForHTTPStatus(t, fmt.Sprintf("http://localhost:%d/metrics", pprofPort), http.StatusNotFound)
}

func TestManagementServersNilAndZeroAreNoops(t *testing.T) {
	var owner *managementServers
	if err := owner.start(nil); err != nil {
		t.Fatalf("nil start: %v", err)
	}
	owner.apply(nil)
	owner.apply(&config.Config{})
	owner.shutdown(context.Background())

	m := &managementServers{}
	if err := m.start(&config.Config{}); err != nil {
		t.Fatalf("zero start: %v", err)
	}
	m.apply(&config.Config{})
	m.shutdown(context.Background())
	if m.endpointServer != nil || m.pprofServer != nil {
		t.Fatalf("zero config started servers: endpoint=%v pprof=%v", m.endpointServer, m.pprofServer)
	}
}

func TestManagementServersShutdownStopsListeners(t *testing.T) {
	port := freeLocalPort(t)
	conf := &config.Config{}
	conf.Global.PprofPort = uint16(port)
	conf.Global.EndpointPrometheusEnabled = true

	m := newTestManagementServers(t)
	if err := m.start(conf); err != nil {
		t.Fatalf("start: %v", err)
	}
	base := fmt.Sprintf("http://localhost:%d/metrics", port)
	waitForHTTPStatus(t, base, http.StatusOK)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	m.shutdown(ctx)
	waitForHTTPDown(t, base)
}
