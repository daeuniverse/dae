/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/metrics"
)

func TestAdoptPreparedGenerationRebindsEndpoint(t *testing.T) {
	portA := freeLocalPort(t)
	portB := freeLocalPort(t)

	confA := &config.Config{}
	confA.Global.EndpointListenAddress = fmt.Sprintf("127.0.0.1:%d", portA)
	confA.Global.EndpointPrometheusEnabled = true

	state := metrics.NewState()
	w := &reloadWorker{
		log:          testManagementLog(),
		conf:         confA,
		metricsState: state,
	}
	w.mgmt = managementServers{
		log:      w.log,
		registry: metrics.NewRegistry(state),
	}
	if err := w.mgmt.start(confA); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { w.mgmt.shutdown(context.Background()) })
	waitForHTTPStatus(t, fmt.Sprintf("http://127.0.0.1:%d/metrics", portA), http.StatusOK)

	confB := &config.Config{}
	confB.Global.EndpointListenAddress = fmt.Sprintf("127.0.0.1:%d", portB)
	confB.Global.EndpointPrometheusEnabled = true
	nextPlane := &control.ControlPlane{}
	w.adoptPreparedGeneration(&runtimeGeneration{
		controlPlane: nextPlane,
		conf:         confB,
	})

	if got := w.metricsState.GetControlPlane(); got != nextPlane {
		t.Fatalf("metrics control plane = %p, want %p", got, nextPlane)
	}
	if w.c != nextPlane || w.conf != confB {
		t.Fatalf("worker generation c=%p conf=%p", w.c, w.conf)
	}
	waitForHTTPDown(t, fmt.Sprintf("http://127.0.0.1:%d/metrics", portA))
	waitForHTTPStatus(t, fmt.Sprintf("http://127.0.0.1:%d/metrics", portB), http.StatusOK)
}
