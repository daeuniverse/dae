/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/control"
)

const (
	probeTimeout               = 5 * time.Second
	probeJobTimeout            = nativeapi.ProbeJobTimeoutMs * time.Millisecond
	probeMaxActiveJobs         = nativeapi.ProbeMaxActiveJobs
	probeMaxQueuedJobs         = nativeapi.ProbeMaxQueuedJobs
	probeMaxMembersPerJob      = nativeapi.ProbeMaxMembersPerJob
	probeMaxResultsPerJob      = nativeapi.ProbeMaxResultsPerJob
	probeGlobalRequestsPerMin  = nativeapi.ProbeRequestsPerMinute
	probeRateLimitWindow       = time.Minute
	probeRateLimitedRetryAfter = 60
)

// probeGate bounds how much probe work a client can queue and how fast it can
// submit it, so the advertised capabilities.limits are actually enforced.
type probeGate struct {
	mu          sync.Mutex
	inFlight    int
	windowStart time.Time
	windowCount int
	slots       chan struct{}
}

func newProbeGate() *probeGate {
	return &probeGate{slots: make(chan struct{}, probeMaxActiveJobs)}
}

// reserve accounts for one accepted probe or reports why it cannot be queued.
func (g *probeGate) reserve(now time.Time) error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.windowStart.IsZero() || now.Sub(g.windowStart) >= probeRateLimitWindow {
		g.windowStart = now
		g.windowCount = 0
	}
	if g.windowCount >= probeGlobalRequestsPerMin {
		return &nativeapi.APIError{
			Status:            429,
			Code:              "rate_limited",
			Message:           "probe request rate limit exceeded",
			RetryAfterSeconds: probeRateLimitedRetryAfter,
		}
	}
	if g.inFlight >= probeMaxActiveJobs+probeMaxQueuedJobs {
		return &nativeapi.APIError{
			Status:            503,
			Code:              "temporarily_unavailable",
			Message:           "probe queue is full",
			RetryAfterSeconds: 1,
		}
	}
	g.windowCount++
	g.inFlight++
	return nil
}

// run waits for a concurrency slot, runs fn, then frees the queue slot.
func (g *probeGate) run(fn func()) {
	if g == nil {
		fn()
		return
	}
	g.slots <- struct{}{}
	defer func() { <-g.slots }()
	defer func() {
		g.mu.Lock()
		g.inFlight--
		g.mu.Unlock()
	}()
	fn()
}

// StartProbe queues one bounded probe operation.
func (o *nativeAPIOperations) StartProbe(ctx context.Context, request nativeapi.ProbeRequest, idempotencyKey string) (nativeapi.OperationAccepted, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	if o == nil || o.store == nil {
		return nativeapi.OperationAccepted{}, nativeapi.NewAPIError(503, "temporarily_unavailable", "the operation store is unavailable")
	}
	accepted, replayed, err := o.store.Accept(nativeapi.OperationKindProbe, idempotencyKey)
	if err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	if replayed {
		return accepted, nil
	}
	if err := o.probes.reserve(time.Now()); err != nil {
		// Nothing was queued, so the key must stay usable for the retry.
		o.store.ReleaseReplayKey(idempotencyKey)
		o.store.Fail(accepted.OperationID, &nativeapi.SafeError{Code: "probe_rejected", Message: err.Error()})
		return nativeapi.OperationAccepted{}, err
	}
	go o.runProbe(accepted.OperationID, request)
	return accepted, nil
}

func (o *nativeAPIOperations) runProbe(operationID string, request nativeapi.ProbeRequest) {
	o.probes.run(func() {
		o.store.Start(operationID)
		o.events.publishOperationUpdated(operationID, "running")
		result, err := o.executeProbe(request)
		if err != nil {
			o.store.Fail(operationID, &nativeapi.SafeError{Code: "probe_failed", Message: err.Error()})
			o.events.publishOperationUpdated(operationID, "failed")
			return
		}
		o.store.Succeed(operationID, result)
		o.events.publishOperationUpdated(operationID, "succeeded")
	})
}

func (o *nativeAPIOperations) executeProbe(request nativeapi.ProbeRequest) (nativeapi.ProbeResult, error) {
	active := o.supervisor.activeSnapshot()
	if active == nil || active.controlPlane == nil {
		return nativeapi.ProbeResult{}, fmt.Errorf("no active runtime generation")
	}
	plane := active.controlPlane
	members, err := probeMembers(plane, request)
	if err != nil {
		return nativeapi.ProbeResult{}, err
	}
	result := nativeapi.ProbeResult{
		Target:           request.Target,
		SelectionChanged: nativeapi.TransportBooleanMap{},
		SelectionBefore:  nativeapi.TransportSelectionMap{},
		SelectionAfter:   nativeapi.TransportSelectionMap{},
		Results:          make([]nativeapi.ProbeResultItem, 0, len(members)*len(request.Transport)),
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeJobTimeout)
	defer cancel()
	soMark := plane.SoMarkFromDae()
	for _, member := range members {
		if ctx.Err() != nil {
			break
		}
		for _, transport := range request.Transport {
			if len(result.Results) >= probeMaxResultsPerJob || ctx.Err() != nil {
				break
			}
			result.Results = append(result.Results, runProbeMember(ctx, member, request, transport, soMark))
		}
	}
	return result, nil
}

type probeMember struct {
	id     string
	dialer *dialer.Dialer
}

func probeMembers(plane *control.ControlPlane, request nativeapi.ProbeRequest) ([]probeMember, error) {
	nodeMap := make(map[string]*dialer.Dialer)
	for _, item := range plane.EgressDialers() {
		if property := item.Property(); property != nil {
			nodeMap[nodeIDOf(property)] = item
		}
	}
	if request.Target.Type == "node" {
		item, ok := nodeMap[request.Target.NodeID]
		if !ok {
			return nil, fmt.Errorf("node not found")
		}
		return []probeMember{{id: request.Target.NodeID, dialer: item}}, nil
	}

	groups := make(map[string]*dialer.Dialer)
	groupDialers := make(map[string][]*dialer.Dialer)
	for _, group := range plane.OutboundGroups() {
		if group == nil {
			continue
		}
		id := groupIDOf(group.Name)
		groupDialers[id] = group.Dialers
		for _, item := range group.Dialers {
			if property := item.Property(); property != nil {
				groups[nodeIDOf(property)] = item
			}
		}
	}
	if _, ok := groupDialers[request.Target.GroupID]; !ok {
		return nil, fmt.Errorf("group not found")
	}

	var selected []string
	if request.Members == nil || len(request.Members.Values) == 0 {
		selected = append(selected, request.Target.GroupID)
	} else {
		for _, value := range request.Members.Values {
			if value == "direct" || value == "leaves" {
				selected = append(selected, request.Target.GroupID)
				continue
			}
			selected = append(selected, value)
		}
	}

	seen := map[string]struct{}{}
	members := make([]probeMember, 0, len(selected))
	addDialers := func(groupID string) {
		for _, item := range groupDialers[groupID] {
			property := item.Property()
			if property == nil {
				continue
			}
			id := nodeIDOf(property)
			if _, duplicate := seen[id]; duplicate {
				continue
			}
			seen[id] = struct{}{}
			members = append(members, probeMember{id: id, dialer: item})
		}
	}
	for _, value := range selected {
		if _, isGroup := groupDialers[value]; isGroup {
			addDialers(value)
			continue
		}
		if item, ok := nodeMap[value]; ok {
			id := value
			if _, duplicate := seen[id]; duplicate {
				continue
			}
			seen[id] = struct{}{}
			members = append(members, probeMember{id: id, dialer: item})
		}
	}
	sort.Slice(members, func(i, j int) bool { return members[i].id < members[j].id })
	if len(members) > probeMaxMembersPerJob {
		return nil, nativeapi.NewAPIError(422, "invalid_request", "probe expands to more members than this engine supports")
	}
	return members, nil
}

func runProbeMember(parent context.Context, member probeMember, request nativeapi.ProbeRequest, transport string, soMark uint32) nativeapi.ProbeResultItem {
	purpose := "data"
	if request.Kind == "dns" {
		purpose = "dns"
	}
	item := nativeapi.ProbeResultItem{
		MemberID:      member.id,
		Kind:          request.Kind,
		Purpose:       purpose,
		Transport:     transport,
		IPVersion:     request.IPVersion,
		Warmth:        request.Warmth,
		State:         "unknown",
		HealthUpdated: false,
		ObservedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	if item.IPVersion == "any" {
		item.IPVersion = "ipv4"
	}
	if member.dialer == nil {
		item.State = "unavailable"
		reason := "dialer is unavailable"
		item.Error = &reason
		return item
	}
	address := "1.1.1.1:443"
	network := "tcp"
	if transport == "udp" {
		network = "udp"
		address = "1.1.1.1:53"
	}
	if item.IPVersion == "ipv6" {
		if network == "udp" {
			address = "[2606:4700:4700::1111]:53"
		} else {
			address = "[2606:4700:4700::1111]:443"
		}
	}
	ctx, cancel := context.WithTimeout(parent, probeTimeout)
	defer cancel()
	started := time.Now()
	conn, err := member.dialer.DialContext(ctx, common.MagicNetwork(network, soMark, false), address)
	elapsed := time.Since(started)
	if err != nil {
		item.State = "unavailable"
		reason := sanitizeLogMessage(err.Error())
		item.Error = &reason
		return item
	}
	if conn != nil {
		_ = conn.Close()
	}
	latency := float64(elapsed.Microseconds()) / 1000
	item.State = "healthy"
	item.LatencyMs = &latency
	return item
}

var _ nativeapi.ProbeProvider = (*nativeAPIOperations)(nil)
