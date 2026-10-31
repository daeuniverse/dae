/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/control"
)

const maxBulkClose = 1000

func nodeIDOfLink(link, name string) string {
	if link != "" {
		return nodeIDPrefix + digest(link)[:idDigestBytes*2]
	}
	return nodeIDPrefix + digest(name)[:idDigestBytes*2]
}

func connectionIDOfFlow(flowID string) string {
	return "c_" + flowID
}

func nativeConnectionOf(flow control.SessionFlowSnapshot) nativeapi.Connection {
	connection := nativeapi.Connection{
		ID:             connectionIDOfFlow(flow.ID),
		State:          "active",
		Src:            flow.Src.String(),
		Dst:            flow.Dst.String(),
		Chain:          []string{},
		ChainSource:    "unknown",
		RuleSource:     "unknown",
		ObservedBy:     "userspace",
		StartedAt:      formatTime(flow.StartedAt),
		RuleID:         nil,
		RuleExpression: nil,
	}
	if flow.ID != "" {
		id := flow.ID
		connection.FlowID = &id
	}
	if flow.Pname != "" {
		name := flow.Pname
		connection.Pname = &name
	}
	if flow.Domain != "" {
		domain := flow.Domain
		connection.Domain = &domain
	}
	if flow.Outbound != "" {
		outbound := flow.Outbound
		connection.Outbound = &outbound
		chain := []string{groupIDOf(flow.Outbound)}
		if flow.DialerName != "" || flow.DialerLink != "" {
			chain = append(chain, nodeIDOfLink(flow.DialerLink, flow.DialerName))
		}
		connection.Chain = chain
		connection.ChainSource = "evaluation"
	}
	if flow.HasBytes {
		up := nativeAPIUInt64(flow.UploadBytes)
		down := nativeAPIUInt64(flow.DownloadBytes)
		connection.UploadBytes = up
		connection.DownloadBytes = down
	}
	return connection
}

// ListConnections returns the live userspace flows.
func (p *nativeAPIProvider) ListConnections(ctx context.Context, filter nativeapi.ConnectionFilter) (nativeapi.ConnectionList, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.ConnectionList{}, err
	}
	plane, err := p.activeControlPlane()
	if err != nil {
		return nativeapi.ConnectionList{}, err
	}
	status := p.status.snapshot()
	list := nativeapi.ConnectionList{
		ObservedAt: time.Now().UTC().Format(time.RFC3339),
		InstanceID: status.InstanceID,
		Visibility: "partial",
		TCP:        []nativeapi.Connection{},
		UDP:        []nativeapi.Connection{},
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = nativeapi.NodeListDefaultLimit
	}
	for _, flow := range plane.ActiveFlowSnapshots() {
		if filter.Type == "tcp" && flow.Network != "tcp" {
			continue
		}
		if filter.Type == "udp" && flow.Network != "udp" {
			continue
		}
		if filter.Src != "" && flow.Src.Addr().String() != filter.Src {
			continue
		}
		connection := nativeConnectionOf(flow)
		if flow.Network == "udp" {
			list.TotalUDP++
			if len(list.UDP) < limit {
				list.UDP = append(list.UDP, connection)
			} else {
				list.Truncated = true
			}
			continue
		}
		list.TotalTCP++
		if len(list.TCP) < limit {
			list.TCP = append(list.TCP, connection)
		} else {
			list.Truncated = true
		}
	}
	return list, nil
}

// CloseConnection closes one live flow by connection ID.
func (p *nativeAPIProvider) CloseConnection(ctx context.Context, connectionID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	plane, err := p.activeControlPlane()
	if err != nil {
		return err
	}
	flowID := connectionID
	if len(flowID) > 2 && flowID[:2] == "c_" {
		flowID = flowID[2:]
	}
	if !plane.CloseFlowByID(flowID) {
		return nativeapi.NewAPIError(404, "resource_not_found", "connection not found")
	}
	return nil
}

// CloseConnections closes every matching live flow.
func (p *nativeAPIProvider) CloseConnections(ctx context.Context, filter nativeapi.ConnectionFilter, all bool) (nativeapi.BulkCloseResult, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.BulkCloseResult{}, err
	}
	plane, err := p.activeControlPlane()
	if err != nil {
		return nativeapi.BulkCloseResult{}, err
	}
	matched := make([]control.SessionFlowSnapshot, 0, 16)
	for _, flow := range plane.ActiveFlowSnapshots() {
		if filter.Type == "tcp" && flow.Network != "tcp" {
			continue
		}
		if filter.Type == "udp" && flow.Network != "udp" {
			continue
		}
		if filter.Src != "" && flow.Src.Addr().String() != filter.Src {
			continue
		}
		if !all && filter.Type == "" && filter.Src == "" {
			continue
		}
		matched = append(matched, flow)
	}
	if len(matched) > maxBulkClose {
		return nativeapi.BulkCloseResult{}, nativeapi.NewAPIError(413, "request_too_large", "selected connections exceed max_bulk_close")
	}
	result := nativeapi.BulkCloseResult{}
	for _, flow := range matched {
		if plane.CloseFlowByID(flow.ID) {
			result.Closed++
		}
	}
	return result, nil
}

func nativeFlowInput(flow control.SessionFlowSnapshot) *nativeapi.FlowInput {
	input := &nativeapi.FlowInput{DomainRuleIDs: []string{}}
	if flow.Src.IsValid() {
		value := flow.Src.String()
		input.Src = &value
	}
	if flow.Dst.IsValid() {
		value := flow.Dst.String()
		input.Dst = &value
	}
	if flow.Domain != "" {
		value := flow.Domain
		input.Domain = &value
	}
	if flow.Pid > 0 {
		value := uint64(flow.Pid)
		input.Pid = &value
	}
	if flow.Dscp > 0 {
		value := uint64(flow.Dscp)
		input.Dscp = &value
	}
	if flow.Mark > 0 {
		value := uint64(flow.Mark)
		input.Mark = &value
	}
	return input
}

func nativeFlowSummary(flow control.SessionFlowHistoryEntry, instanceID string) nativeapi.FlowSummary {
	summary := nativeapi.FlowSummary{
		ID:          flow.ID,
		InstanceID:  instanceID,
		Revision:    flow.Revision,
		Network:     flow.Network,
		State:       flow.State,
		Chain:       []string{},
		ChainSource: "unknown",
		RuleSource:  "unknown",
		ObservedBy:  "userspace",
		StartedAt:   formatTime(flow.StartedAt),
		EndedAt:     formatTime(flow.EndedAt),
		TraceStatus: "disabled",
		Input:       nativeFlowInput(flow.SessionFlowSnapshot),
	}
	if summary.Revision == 0 {
		summary.Revision = 1
	}
	if flow.Pname != "" {
		value := flow.Pname
		summary.Pname = &value
	}
	if flow.Outbound != "" {
		value := flow.Outbound
		summary.Outbound = &value
		chain := []string{groupIDOf(flow.Outbound)}
		if flow.DialerName != "" || flow.DialerLink != "" {
			chain = append(chain, nodeIDOfLink(flow.DialerLink, flow.DialerName))
		}
		summary.Chain = chain
		summary.ChainSource = "evaluation"
	}
	return summary
}

func nativeFlowCoverage() nativeapi.FlowCoverage {
	return nativeapi.FlowCoverage{
		UserspaceTCP: "partial",
		UserspaceUDP: "partial",
		KernelDirect: "none",
		KernelBlock:  "none",
		DNSIntercept: "none",
		KernelBypass: "none",
	}
}

// ListFlows returns the retained closed-flow history, newest first.
func (p *nativeAPIProvider) ListFlows(ctx context.Context, filter nativeapi.FlowFilter) (nativeapi.FlowList, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.FlowList{}, err
	}
	plane, err := p.activeControlPlane()
	if err != nil {
		return nativeapi.FlowList{}, err
	}
	status := p.status.snapshot()
	entries, _ := plane.FlowHistory()
	matched := make([]control.SessionFlowHistoryEntry, 0, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if filter.Network != "" && entry.Network != filter.Network {
			continue
		}
		if filter.State != "" && entry.State != filter.State {
			continue
		}
		if filter.ConnectionID != "" {
			continue
		}
		matched = append(matched, entry)
	}
	now := time.Now()
	bind := pageCursorBind(filter.Network, filter.State, filter.ConnectionID, filter.Limit)
	offset := 0
	if filter.Cursor != "" {
		parsed, err := decodePageCursor("flows", bind, filter.Cursor, now)
		if err != nil {
			return nativeapi.FlowList{}, err
		}
		offset = parsed
	}
	start, end, next := pageOf(len(matched), offset, filter.Limit, "flows", bind, now)
	dropped := "0"
	list := nativeapi.FlowList{
		InstanceID:     status.InstanceID,
		ObservedAt:     now.UTC().Format(time.RFC3339),
		Coverage:       nativeFlowCoverage(),
		DroppedRecords: &dropped,
		Flows:          make([]nativeapi.FlowSummary, 0, end-start),
		NextCursor:     next,
	}
	for _, entry := range matched[start:end] {
		list.Flows = append(list.Flows, nativeFlowSummary(entry, status.InstanceID))
	}
	return list, nil
}

// GetFlow returns one retained flow's detail.
func (p *nativeAPIProvider) GetFlow(ctx context.Context, flowID string) (*nativeapi.FlowDetail, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	plane, err := p.activeControlPlane()
	if err != nil {
		return nil, err
	}
	status := p.status.snapshot()
	entry, ok := plane.FlowHistoryByID(flowID)
	if !ok {
		return nil, nativeapi.NewAPIError(410, "flow_expired", "flow is no longer retained")
	}
	summary := nativeFlowSummary(entry, status.InstanceID)
	detail := &nativeapi.FlowDetail{
		FlowSummary: summary,
		Input:       summary.Input,
		Trace: &nativeapi.FlowTrace{
			Status:  "disabled",
			Missing: []string{"not_instrumented"},
			Steps:   []any{},
		},
	}
	return detail, nil
}

var (
	_ nativeapi.ConnectionProvider = (*nativeAPIProvider)(nil)
	_ nativeapi.FlowProvider       = (*nativeAPIProvider)(nil)
)
