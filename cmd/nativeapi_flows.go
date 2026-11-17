/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"sort"
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

func (p *nativeAPIProvider) nativeConnectionOf(flow control.SessionFlowSnapshot) nativeapi.Connection {
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
	if flow.HasBytes && p.connectionBytes {
		up := nativeAPIUInt64(flow.UploadBytes)
		down := nativeAPIUInt64(flow.DownloadBytes)
		connection.UploadBytes = up
		connection.DownloadBytes = down
	}
	return connection
}

// connectionFlowMatches reports whether a flow passes the request's type and
// source filters.
func connectionFlowMatches(flow control.SessionFlowSnapshot, filter nativeapi.ConnectionFilter) bool {
	if filter.Type != "" && flow.Network != filter.Type {
		return false
	}
	if filter.Src != "" && flow.Src.Addr().String() != filter.Src {
		return false
	}
	return true
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
	// Sorting has to see every match before the limit truncates, so the filter
	// collects first and truncates after ordering.
	flows := make([]control.SessionFlowSnapshot, 0, 64)
	var totalTCP, totalUDP uint64
	for _, flow := range plane.ActiveFlowSnapshots() {
		if !connectionFlowMatches(flow, filter) {
			continue
		}
		if flow.Network == "udp" {
			totalUDP++
		} else {
			totalTCP++
		}
		flows = append(flows, flow)
	}
	var windows map[string]flowWindowBytes
	if filter.WindowSeconds > 0 && p.connectionBytes {
		windows = p.flowWindows().measure(flows, time.Duration(filter.WindowSeconds)*time.Second)
	}
	if filter.Sort != "" {
		sortConnectionFlows(flows, filter.Sort, filter.Order, windows)
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = nativeapi.NodeListDefaultLimit
	}
	tcpFlows, udpFlows, truncated := selectConnectionFlows(flows, limit)
	list := nativeapi.ConnectionList{
		ObservedAt: time.Now().UTC().Format(time.RFC3339),
		InstanceID: status.InstanceID,
		Visibility: "partial",
		Truncated:  truncated,
		TCP:        make([]nativeapi.Connection, 0, len(tcpFlows)),
		UDP:        make([]nativeapi.Connection, 0, len(udpFlows)),
		TotalTCP:   totalTCP,
		TotalUDP:   totalUDP,
	}
	if filter.WindowSeconds > 0 {
		list.Window = &nativeapi.ConnectionWindow{Seconds: filter.WindowSeconds}
	}
	for _, flow := range tcpFlows {
		list.TCP = append(list.TCP, p.connectionOf(flow, windows))
	}
	for _, flow := range udpFlows {
		list.UDP = append(list.UDP, p.connectionOf(flow, windows))
	}
	return list, nil
}

// selectConnectionFlows applies the per-network limit to ordered matches. The
// limit binds each network separately, which is what `total_tcp` / `total_udp`
// and `truncated` describe.
func selectConnectionFlows(flows []control.SessionFlowSnapshot, limit int) (tcpFlows, udpFlows []control.SessionFlowSnapshot, truncated bool) {
	tcpFlows = make([]control.SessionFlowSnapshot, 0, min(limit, len(flows)))
	for _, flow := range flows {
		if flow.Network == "udp" {
			if len(udpFlows) < limit {
				udpFlows = append(udpFlows, flow)
			} else {
				truncated = true
			}
			continue
		}
		if len(tcpFlows) < limit {
			tcpFlows = append(tcpFlows, flow)
		} else {
			truncated = true
		}
	}
	return tcpFlows, udpFlows, truncated
}

// connectionOf projects one flow, attaching the trailing-window bytes when the
// request measured them. A flow without a baseline keeps the fields absent.
func (p *nativeAPIProvider) connectionOf(flow control.SessionFlowSnapshot, windows map[string]flowWindowBytes) nativeapi.Connection {
	connection := p.nativeConnectionOf(flow)
	// The window bytes derive from the same counters `disable_connection_bytes`
	// hides, so they go with them.
	if !p.connectionBytes {
		return connection
	}
	if window, ok := windows[flow.ID]; ok {
		connection.UploadWindowBytes = nativeAPIUInt64(window.upload)
		connection.DownloadWindowBytes = nativeAPIUInt64(window.download)
	}
	return connection
}

// sortConnectionFlows orders matches in place. Connections whose counters are
// unknown sort last in either direction: an unknown byte count is not zero.
func sortConnectionFlows(flows []control.SessionFlowSnapshot, field, order string, windows map[string]flowWindowBytes) {
	rank := func(flow control.SessionFlowSnapshot) (uint64, bool) {
		switch field {
		case "download":
			if !flow.HasBytes {
				return 0, false
			}
			return flow.DownloadBytes, true
		case "upload":
			if !flow.HasBytes {
				return 0, false
			}
			return flow.UploadBytes, true
		case "total":
			if !flow.HasBytes {
				return 0, false
			}
			return flow.UploadBytes + flow.DownloadBytes, true
		}
		window, ok := windows[flow.ID]
		if !ok {
			return 0, false
		}
		switch field {
		case "window_download":
			return window.download, true
		case "window_upload":
			return window.upload, true
		default:
			return window.upload + window.download, true
		}
	}
	sort.SliceStable(flows, func(i, j int) bool {
		left, leftKnown := rank(flows[i])
		right, rightKnown := rank(flows[j])
		if leftKnown != rightKnown {
			return leftKnown
		}
		if !leftKnown || left == right {
			return false
		}
		if order == "asc" {
			return left < right
		}
		return left > right
	})
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
		if !connectionFlowMatches(flow, filter) {
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
	if flow.ID != "" {
		// The id a client can pass to /connections; it is derived from the flow id
		// so both resources name the same exchange.
		connectionID := connectionIDOfFlow(flow.ID)
		summary.ConnectionID = &connectionID
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

// matchingFlows applies the flow filters to the active snapshot and the closed
// history. connection_id is an exact match over active and retained flows; the
// history only holds closed ones, so a filter naming a connection that is still
// open must also consult the active snapshot. Active flows come first because
// they are the newest.
func matchingFlows(active []control.SessionFlowSnapshot, entries []control.SessionFlowHistoryEntry, filter nativeapi.FlowFilter) []control.SessionFlowHistoryEntry {
	// `all` is a contract selector, not a literal network/state value.
	networkFilter := filter.Network
	if networkFilter == "all" {
		networkFilter = ""
	}
	stateFilter := filter.State
	if stateFilter == "all" {
		stateFilter = ""
	}
	matched := make([]control.SessionFlowHistoryEntry, 0, len(entries)+1)
	if filter.ConnectionID != "" {
		for _, flow := range active {
			if connectionIDOfFlow(flow.ID) != filter.ConnectionID {
				continue
			}
			if networkFilter != "" && flow.Network != networkFilter {
				continue
			}
			entry := control.SessionFlowHistoryEntry{SessionFlowSnapshot: flow, State: "active"}
			if stateFilter != "" && entry.State != stateFilter {
				continue
			}
			matched = append(matched, entry)
		}
	}
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if networkFilter != "" && entry.Network != networkFilter {
			continue
		}
		if stateFilter != "" && entry.State != stateFilter {
			continue
		}
		if filter.ConnectionID != "" && connectionIDOfFlow(entry.ID) != filter.ConnectionID {
			// The contract defines connection_id as an exact match over active and
			// retained flows, so filter instead of discarding every entry.
			continue
		}
		matched = append(matched, entry)
	}
	return matched
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
	matched := matchingFlows(plane.ActiveFlowSnapshots(), entries, filter)
	now := time.Now()
	bind := pageCursorBind(filter.Network, filter.State, filter.ConnectionID, filter.Limit)
	after, expectNext, oldest := "", "", ""
	if filter.Cursor != "" {
		parsed, next, cursorOldest, err := decodePageCursorNext(status.InstanceID, "flows", bind, filter.Cursor, now)
		if err != nil {
			return nativeapi.FlowList{}, err
		}
		after, expectNext, oldest = parsed, next, cursorOldest
	}
	// Flow IDs are stable across reads, so they anchor the walk while finished
	// flows keep arriving at the head of the history.
	page, next, err := pageAfterExpecting(matched, func(entry control.SessionFlowHistoryEntry) string { return entry.ID }, after, expectNext, oldest, filter.Limit, status.InstanceID, "flows", bind, now)
	if err != nil {
		return nativeapi.FlowList{}, err
	}
	dropped := "0"
	list := nativeapi.FlowList{
		InstanceID:     status.InstanceID,
		ObservedAt:     now.UTC().Format(time.RFC3339),
		Coverage:       nativeFlowCoverage(),
		DroppedRecords: &dropped,
		Flows:          make([]nativeapi.FlowSummary, 0, len(page)),
		NextCursor:     next,
	}
	for _, entry := range page {
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
		// /connections exposes live flow ids; a GET of that id must return the
		// live record instead of 410 until the flow closes and enters history.
		for _, flow := range plane.ActiveFlowSnapshots() {
			if flow.ID == flowID {
				entry = control.SessionFlowHistoryEntry{SessionFlowSnapshot: flow, State: "active"}
				ok = true
				break
			}
		}
	}
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
