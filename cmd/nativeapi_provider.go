/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/config"
)

// nativeAPIConfig maps dae configuration onto the native listener. The engine
// identity comes from the same values `dae -v` prints, so a frontend never
// reports a version the command line disagrees with.
func nativeAPIConfig(conf *config.Config) nativeapi.Config {
	return nativeapi.Config{
		Listen:                 conf.Api.Listen,
		Secret:                 conf.Api.Secret,
		AllowAnonymousLoopback: conf.Api.AllowAnonymousLoopback,
		AllowOrigins:           conf.Api.AllowOrigins,
		AllowedHosts:           conf.Api.AllowedHosts,
		UI:                     conf.Api.UI,
		EngineName:             nativeapi.EngineName,
		EngineVersion:          config.Version,
		BuildRevision:          build.Revision,
		BuildTarget:            build.Target,
		BuildBuiltAt:           build.BuildTime,
	}
}

type nativeAPIProvider struct {
	supervisor *runtimeSupervisor
	status     *runtimeStatus
}

func (p *nativeAPIProvider) SnapshotRuntime(ctx context.Context, detail string) (nativeapi.Runtime, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.Runtime{}, err
	}
	active := p.supervisor.activeSnapshot()
	if active == nil || active.controlPlane == nil {
		return nativeapi.Runtime{}, fmt.Errorf("no active runtime generation")
	}

	status := p.status.snapshot()
	now := time.Now()
	stats := active.controlPlane.SnapshotRuntimeStats(3600, 180)

	state := status.State
	if state == "" {
		state = string(runtimeStateRunning)
	}
	generationState := "active"
	if state == string(runtimeStateReloading) {
		generationState = "reloading"
	}
	datapathState := "active"
	if state == string(runtimeStateSuspended) {
		// A suspended daemon keeps no inbound/outbound datapath attached.
		datapathState = "disabled"
	}

	activeID := active.id
	if activeID == "" {
		activeID = "gen-unknown"
	}

	runtime := nativeapi.Runtime{
		ObservedAt: now.UTC().Format(time.RFC3339),
		InstanceID: status.InstanceID,
		Lifecycle: nativeapi.Lifecycle{
			State:         state,
			StartedAt:     formatTime(status.StartedAt),
			UptimeSeconds: formatUptime(now.Sub(status.StartedAt)),
		},
		Generation: nativeapi.Generation{
			ActiveID:       activeID,
			ConfigRevision: nonEmptyString(active.configRevision),
			State:          generationState,
			ActivatedAt:    formatTime(active.activatedAt),
		},
		Datapath: nativeapi.DatapathSummary{
			Kind:       "ebpf",
			State:      datapathState,
			Visibility: "partial",
			Ebpf:       nil,
		},
		Traffic: nativeapi.TrafficSummary{
			Scope:        "visible",
			ObservedBy:   "userspace",
			CounterSince: formatTime(active.activatedAt),
			SampledAt:    formatTime(stats.UpdatedAt),
			Connections: nativeapi.Connections{
				TCP:   uint64Pointer(uint64(stats.ActiveConnections)),
				UDP:   uint64Pointer(uint64(stats.UDPSessions)),
				Total: uint64Pointer(uint64(stats.ActiveConnections + stats.UDPSessions)),
			},
			Bytes: nativeapi.Bytes{
				Upload:   stringPointer(strconv.FormatUint(stats.UploadTotal, 10)),
				Download: stringPointer(strconv.FormatUint(stats.DownloadTotal, 10)),
			},
			Rates: &nativeapi.Rates{
				WindowSeconds:          1,
				UploadBytesPerSecond:   stringPointer(strconv.FormatUint(stats.UploadRate, 10)),
				DownloadBytesPerSecond: stringPointer(strconv.FormatUint(stats.DownloadRate, 10)),
			},
		},
		Process: nativeapi.Process{
			CPUPercent: nil,
		},
	}
	if detail == "full" {
		pid := uint32(os.Getpid())
		runtime.Process.Pid = &pid
	}
	if status.LastReload != nil {
		record := status.LastReload
		lastReload := &nativeapi.LastReload{
			OperationID: record.OperationID,
			Status:      record.Status,
			FinishedAt:  formatTime(record.FinishedAt),
		}
		if record.Error != "" {
			lastReload.Error = &nativeapi.SafeError{
				Code:    "reload_failed",
				Message: record.Error,
			}
		}
		runtime.LastReload = lastReload
	}
	return runtime, nil
}

func formatTime(value time.Time) *string {
	if value.IsZero() {
		return nil
	}
	formatted := value.UTC().Format(time.RFC3339)
	return &formatted
}

func formatUptime(value time.Duration) *string {
	if value < 0 {
		value = 0
	}
	seconds := strconv.FormatUint(uint64(value/time.Second), 10)
	return &seconds
}

func nonEmptyString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func stringPointer(value string) *string {
	return &value
}

func uint64Pointer(value uint64) *uint64 {
	return &value
}

var (
	_ nativeapi.GroupProvider          = (*nativeAPIProvider)(nil)
	_ nativeapi.NodeProvider           = (*nativeAPIProvider)(nil)
	_ nativeapi.TrafficHistoryProvider = (*nativeAPIProvider)(nil)
	_ nativeapi.OperationProvider      = (*nativeAPIOperations)(nil)
)
