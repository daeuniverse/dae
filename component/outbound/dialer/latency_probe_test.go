/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

func configureLatencyProbeDialer(t *testing.T, d *Dialer, serverURL string) {
	t.Helper()

	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("Parse(%q) error = %v", serverURL, err)
	}
	d.TcpCheckOptionRaw.Reset()
	d.TcpCheckOptionRaw.Raw = []string{serverURL, u.Hostname()}
	d.TcpCheckOptionRaw.Method = http.MethodGet
}

func TestDialerProbeLatencyFastDoesNotMutateHealthState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	d := newTestDialer(t)
	configureLatencyProbeDialer(t, d, server.URL)

	result, err := d.ProbeLatencyFast()
	if err != nil {
		t.Fatalf("ProbeLatencyFast() error = %v", err)
	}
	if result == nil {
		t.Fatal("ProbeLatencyFast() returned nil result")
	}
	if !result.Alive {
		t.Fatalf("ProbeLatencyFast() alive = false, message = %q", result.Message)
	}
	if result.Latency <= 0 {
		t.Fatalf("ProbeLatencyFast() latency = %v, want > 0", result.Latency)
	}
	if result.CheckedAt.IsZero() {
		t.Fatal("ProbeLatencyFast() should stamp CheckedAt")
	}

	networkType := &NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
	}
	if got := d.MustGetLatencies10(networkType).Len(); got != 0 {
		t.Fatalf("fast probe should not append latency samples, got %d", got)
	}
}

func TestDialerProbeLatencyRecordsBestLatency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	d := newTestDialer(t)
	configureLatencyProbeDialer(t, d, server.URL)

	result, err := d.ProbeLatency()
	if err != nil {
		t.Fatalf("ProbeLatency() error = %v", err)
	}
	if result == nil {
		t.Fatal("ProbeLatency() returned nil result")
	}
	if !result.Alive {
		t.Fatalf("ProbeLatency() alive = false, message = %q", result.Message)
	}
	if result.Latency <= 0 {
		t.Fatalf("ProbeLatency() latency = %v, want > 0", result.Latency)
	}

	networkType := &NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
	}
	lastLatency, ok := d.MustGetLatencies10(networkType).LastLatency()
	if !ok {
		t.Fatal("ProbeLatency() should append a latency sample")
	}
	if result.Latency != lastLatency {
		t.Fatalf("ProbeLatency() latency = %v, want last sample %v", result.Latency, lastLatency)
	}
}
