/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/control"
)

func (p *nativeAPIProvider) activeControlPlane() (*control.ControlPlane, error) {
	active := p.supervisor.activeSnapshot()
	if active == nil || active.controlPlane == nil {
		return nil, fmt.Errorf("no active runtime generation")
	}
	return active.controlPlane, nil
}

func nativeAPIUInt64(value uint64) *string {
	formatted := strconv.FormatUint(value, 10)
	return &formatted
}

func nativeAPISafeUInt(value int64) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

// RoutingRules projects the running generation's routing dictionary.
func (p *nativeAPIProvider) RoutingRules(ctx context.Context) (nativeapi.RuleList, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.RuleList{}, err
	}
	plane, err := p.activeControlPlane()
	if err != nil {
		return nativeapi.RuleList{}, err
	}
	snapshot := plane.SnapshotRoutingRules()
	list := nativeapi.RuleList{
		GenerationID: snapshot.GenerationID,
		Rules:        make([]nativeapi.RoutingRule, 0, len(snapshot.Rules)+1),
		Fallback:     nativeapi.RuleFallback{Outbound: snapshot.FallbackOutbound, Source: nil},
	}
	for index, rule := range snapshot.Rules {
		list.Rules = append(list.Rules, nativeapi.RoutingRule{
			RuleID:     "traffic:" + strconv.Itoa(index),
			Index:      uint64(index),
			Expression: rule.Expression,
			Outbound:   rule.Outbound,
			Must:       rule.Must,
			Source:     nil,
			Kind:       "rule",
		})
	}
	fallbackIndex := len(list.Rules)
	list.Rules = append(list.Rules, nativeapi.RoutingRule{
		RuleID:     "traffic:fallback",
		Index:      uint64(fallbackIndex),
		Expression: "fallback: " + snapshot.FallbackOutbound,
		Outbound:   snapshot.FallbackOutbound,
		Must:       false,
		Source:     nil,
		Kind:       "fallback",
	})
	return list, nil
}

// RuntimeOutbounds projects the process-level per-outbound counters.
func (p *nativeAPIProvider) RuntimeOutbounds(ctx context.Context) (nativeapi.RuntimeOutbounds, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.RuntimeOutbounds{}, err
	}
	plane, err := p.activeControlPlane()
	if err != nil {
		return nativeapi.RuntimeOutbounds{}, err
	}
	snapshot := plane.SnapshotOutboundCounters()
	since := snapshot.CounterSince
	if since.IsZero() {
		since = snapshot.ObservedAt
	}
	result := nativeapi.RuntimeOutbounds{
		ObservedAt:   snapshot.ObservedAt.UTC().Format(time.RFC3339),
		CounterSince: since.UTC().Format(time.RFC3339),
		Outbounds:    make([]nativeapi.OutboundCounters, 0, len(snapshot.Outbounds)),
	}
	for _, outbound := range snapshot.Outbounds {
		result.Outbounds = append(result.Outbounds, nativeapi.OutboundCounters{
			Name:              outbound.Name,
			Kind:              outbound.Kind,
			ActiveConnections: nativeAPISafeUInt(outbound.ActiveConnections),
			TotalConnections:  *nativeAPIUInt64(outbound.TotalConnections),
			UploadBytes:       *nativeAPIUInt64(outbound.UploadBytes),
			DownloadBytes:     *nativeAPIUInt64(outbound.DownloadBytes),
			Errors:            *nativeAPIUInt64(outbound.Errors),
		})
	}
	return result, nil
}

// SnapshotMemory reads the current process and cgroup memory.
func (p *nativeAPIProvider) SnapshotMemory(ctx context.Context) (nativeapi.RuntimeMemory, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.RuntimeMemory{}, err
	}
	plane, err := p.activeControlPlane()
	if err != nil {
		return nativeapi.RuntimeMemory{}, err
	}
	return nativeAPIMemory(plane.MemorySnapshot()), nil
}

// MemoryHistory serves the retained memory samples.
func (p *nativeAPIProvider) MemoryHistory(ctx context.Context, windowSeconds, maxPoints int) (nativeapi.MemoryHistory, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.MemoryHistory{}, err
	}
	plane, err := p.activeControlPlane()
	if err != nil {
		return nativeapi.MemoryHistory{}, err
	}
	snapshot := plane.MemoryHistory(windowSeconds, maxPoints)
	history := nativeapi.MemoryHistory{
		ObservedAt:          snapshot.ObservedAt.UTC().Format(time.RFC3339),
		WindowSeconds:       snapshot.WindowSeconds,
		SampledEverySeconds: snapshot.SampledEverySeconds,
		Samples:             make([]nativeapi.MemoryHistorySample, 0, len(snapshot.Samples)),
	}
	for _, sample := range snapshot.Samples {
		history.Samples = append(history.Samples, nativeapi.MemoryHistorySample{
			SampledAt:          sample.SampledAt.UTC().Format(time.RFC3339),
			RSSBytes:           optionalUInt64(sample.RSSBytes),
			CgroupCurrentBytes: optionalUInt64(sample.CgroupCurrentBytes),
			KernelEbpfBytes:    optionalUInt64(sample.KernelEbpfBytes),
		})
	}
	return history, nil
}

// MemoryMetrics reports the metrics this process can observe.
func (p *nativeAPIProvider) MemoryMetrics(ctx context.Context) []string {
	if err := ctx.Err(); err != nil {
		return nil
	}
	plane, err := p.activeControlPlane()
	if err != nil {
		return nil
	}
	return plane.MemoryMetrics()
}

func optionalUInt64(value *uint64) *string {
	if value == nil {
		return nil
	}
	return nativeAPIUInt64(*value)
}

func nativeAPIMemory(snapshot control.MemorySnapshot) nativeapi.RuntimeMemory {
	memory := nativeapi.RuntimeMemory{
		ObservedAt: snapshot.ObservedAt.UTC().Format(time.RFC3339),
	}
	if snapshot.RSSBytes != nil {
		memory.Process = &nativeapi.MemoryProcess{RSSBytes: nativeAPIUInt64(*snapshot.RSSBytes)}
	}
	if snapshot.Cgroup != nil {
		cgroup := &nativeapi.MemoryCgroup{
			Scope:        snapshot.Cgroup.Scope,
			CurrentBytes: optionalUInt64(snapshot.Cgroup.CurrentBytes),
			LimitBytes:   optionalUInt64(snapshot.Cgroup.LimitBytes),
		}
		if events := snapshot.Cgroup.Events; events != nil {
			cgroup.Events = &nativeapi.MemoryCgroupEvents{
				High:    optionalUInt64(events.High),
				OOM:     optionalUInt64(events.OOM),
				OOMKill: optionalUInt64(events.OOMKill),
			}
		}
		memory.Cgroup = cgroup
	}
	if snapshot.Kernel != nil {
		memory.Kernel = &nativeapi.MemoryKernel{
			EbpfBytes: optionalUInt64(snapshot.Kernel.EbpfBytes),
			SampledAt: formatTime(snapshot.Kernel.SampledAt),
		}
	}
	return memory
}

// SnapshotDatapath projects the detailed eBPF datapath state.
func (p *nativeAPIProvider) SnapshotDatapath(ctx context.Context, detail string) (nativeapi.Datapath, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.Datapath{}, err
	}
	plane, err := p.activeControlPlane()
	if err != nil {
		return nativeapi.Datapath{}, err
	}
	status := p.status.snapshot()
	snapshot := plane.SnapshotDatapathSummary()
	if detail == "full" {
		snapshot = plane.SnapshotDatapath()
	}

	kind := "ebpf"
	if snapshot.Ebpf.Backend != "real" {
		kind = "unknown"
	}
	state := "active"
	if status.State == string(runtimeStateSuspended) {
		state = "disabled"
	}
	ebpf := nativeAPIEbpfDetail(snapshot.Ebpf)
	if detail != "full" {
		// The summary body keeps the cheap summary fields and omits the
		// detail lists the contract marks optional.
		ebpf.Attachments = nil
		ebpf.Maps = nil
	}
	datapath := nativeapi.Datapath{
		ObservedAt: snapshot.ObservedAt.UTC().Format(time.RFC3339),
		Kind:       kind,
		State:      state,
		Visibility: "partial",
		Ebpf:       ebpf,
		Errors:     []nativeapi.SafeError{},
	}
	return datapath, nil
}

func nativeAPIEbpfSummary(snapshot control.EbpfSnapshot) nativeapi.EbpfSummary {
	return nativeapi.EbpfSummary{
		Backend:  snapshot.Backend,
		Programs: snapshot.Programs,
		Hooks:    snapshot.Hooks,
		Routing: nativeapi.EbpfRoutingSummary{
			State:        snapshot.RoutingState,
			GenerationID: nonEmptyString(snapshot.GenerationID),
			Epoch:        nonEmptyString(snapshot.Epoch),
		},
		Health:    snapshot.Health,
		LastError: nonEmptyString(snapshot.LastError),
		CheckedAt: snapshot.CheckedAt.UTC().Format(time.RFC3339),
	}
}

func nativeAPIEbpfDetail(snapshot control.EbpfSnapshot) *nativeapi.EbpfDetail {
	detail := &nativeapi.EbpfDetail{EbpfSummary: nativeAPIEbpfSummary(snapshot)}
	for _, attachment := range snapshot.Attachments {
		item := nativeapi.EbpfAttachment{
			Name:  attachment.Name,
			Kind:  attachment.Kind,
			State: attachment.State,
		}
		switch attachment.Kind {
		case "interface":
			item.Interface = attachment.Interface
			item.Direction = attachment.Direction
		case "other":
			item.Hook = attachment.Hook
		}
		detail.Attachments = append(detail.Attachments, item)
	}
	detail.Maps = &nativeapi.EbpfMaps{State: "unknown"}
	if occupancy := snapshot.ConnStateOccupancy; occupancy != nil {
		state := "ready"
		if !occupancy.OccupancyKnown {
			state = "partial"
		}
		detail.Maps = &nativeapi.EbpfMaps{
			State: state,
			ConnState: &nativeapi.MapOccupancy{
				Occupancy:      occupancy.Occupancy,
				Capacity:       occupancy.Capacity,
				OccupancyKnown: occupancy.OccupancyKnown,
			},
		}
	}
	return detail
}
