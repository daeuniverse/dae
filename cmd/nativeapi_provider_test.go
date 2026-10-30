/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/control"
	"github.com/sirupsen/logrus"
)

func TestNativeAPIProviderSnapshot(t *testing.T) {
	status := newRuntimeStatus()
	status.setState(runtimeStateRunning)
	status.recordLastReload("op-test", "succeeded", nil)

	conf, err := emptyConfig()
	if err != nil {
		t.Fatal(err)
	}
	generation := newRuntimeGeneration(&control.ControlPlane{}, nil, nil, conf)
	provider := &nativeAPIProvider{
		supervisor: newRuntimeSupervisor(generation),
		status:     status,
	}

	runtime, err := provider.SnapshotRuntime(context.Background(), "summary")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.InstanceID != status.instanceID {
		t.Fatalf("instance_id = %q, want %q", runtime.InstanceID, status.instanceID)
	}
	if runtime.Generation.ActiveID != generation.id {
		t.Fatalf("generation.active_id = %q, want %q", runtime.Generation.ActiveID, generation.id)
	}
	if runtime.Generation.ConfigRevision == nil || *runtime.Generation.ConfigRevision != generation.configRevision {
		t.Fatalf("generation.config_revision = %v, want %q", runtime.Generation.ConfigRevision, generation.configRevision)
	}
	if runtime.Lifecycle.State != string(runtimeStateRunning) {
		t.Fatalf("lifecycle.state = %q", runtime.Lifecycle.State)
	}
	if runtime.Datapath.Kind != "ebpf" || runtime.Datapath.Visibility != "partial" {
		t.Fatalf("datapath = %#v", runtime.Datapath)
	}
	if runtime.Traffic.Bytes.Upload == nil || runtime.Traffic.Bytes.Download == nil {
		t.Fatalf("traffic bytes must be present: %#v", runtime.Traffic.Bytes)
	}
	if runtime.Process.Pid != nil {
		t.Fatal("summary detail must not include process.pid")
	}
	if runtime.LastReload == nil || runtime.LastReload.OperationID != "op-test" || runtime.LastReload.Status != "succeeded" {
		t.Fatalf("last_reload = %#v", runtime.LastReload)
	}

	full, err := provider.SnapshotRuntime(context.Background(), "full")
	if err != nil {
		t.Fatal(err)
	}
	if full.Process.Pid == nil {
		t.Fatal("full detail must include process.pid")
	}
}

// A suspended daemon has no datapath attached; reporting "active" would claim
// traffic is flowing through an engine that is intentionally idle.
func TestNativeAPIProviderSuspendedDatapath(t *testing.T) {
	status := newRuntimeStatus()
	status.setState(runtimeStateSuspended)
	conf, err := emptyConfig()
	if err != nil {
		t.Fatal(err)
	}
	generation := newRuntimeGeneration(&control.ControlPlane{}, nil, nil, conf)
	provider := &nativeAPIProvider{supervisor: newRuntimeSupervisor(generation), status: status}

	runtime, err := provider.SnapshotRuntime(context.Background(), "summary")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Datapath.State != "disabled" {
		t.Fatalf("datapath.state = %q, want disabled", runtime.Datapath.State)
	}
	if runtime.Lifecycle.State != string(runtimeStateSuspended) {
		t.Fatalf("lifecycle.state = %q", runtime.Lifecycle.State)
	}
}

func TestRuntimeStatusSnapshotCopiesLastReload(t *testing.T) {
	status := newRuntimeStatus()
	status.setState(runtimeStateSuspended)
	status.recordLastReload("op-1", "failed", context.Canceled)

	snapshot := status.snapshot()
	if snapshot.State != string(runtimeStateSuspended) {
		t.Fatalf("state = %q", snapshot.State)
	}
	if snapshot.LastReload == nil || snapshot.LastReload.OperationID != "op-1" {
		t.Fatalf("last_reload = %#v", snapshot.LastReload)
	}
	if snapshot.LastReload.Error == "" {
		t.Fatal("last_reload error should be recorded")
	}
	// The snapshot must not alias the live record.
	snapshot.LastReload.OperationID = "mutated"
	next := status.snapshot()
	if next.LastReload.OperationID != "op-1" {
		t.Fatal("runtimeStatus snapshot aliases the live lastReload record")
	}
}

func TestAPIVersionEndpointMatchesCommandLine(t *testing.T) {
	status := newRuntimeStatus()
	status.setState(runtimeStateRunning)
	conf, err := emptyConfig()
	if err != nil {
		t.Fatal(err)
	}
	conf.Api.Enabled = true
	conf.Api.Secret = "operator-token-123456"

	generation := newRuntimeGeneration(&control.ControlPlane{}, nil, nil, conf)
	provider := &nativeAPIProvider{supervisor: newRuntimeSupervisor(generation), status: status}
	server, err := nativeapi.NewServer(nativeAPIConfig(conf), provider, logrus.New())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	req.Host = "127.0.0.1:9527"
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer operator-token-123456")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("version status = %d: %s", recorder.Code, recorder.Body.String())
	}

	var body struct {
		Engine struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"engine"`
		Build *struct {
			Revision *string `json:"revision"`
			Target   *string `json:"target"`
			BuiltAt  *string `json:"built_at"`
		} `json:"build"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	t.Logf("GET /api/v1/version -> %s", recorder.Body.String())
	if commandLine := strings.SplitN(rootCmd.Version, "\n", 2)[0]; body.Engine.Version != commandLine {
		t.Fatalf("engine.version = %q, `dae -v` prints %q", body.Engine.Version, commandLine)
	}
	if body.Engine.Name != nativeapi.EngineName {
		t.Fatalf("engine.name = %q", body.Engine.Name)
	}
	if body.Build == nil || body.Build.Target == nil || *body.Build.Target == "" {
		t.Fatalf("build metadata missing: %#v", body.Build)
	}
	if build.Revision != "" {
		if body.Build.Revision == nil || *body.Build.Revision != build.Revision {
			t.Fatalf("build.revision = %v, want %q", body.Build.Revision, build.Revision)
		}
	}
}
