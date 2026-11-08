/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/net/dns/dnsmessage"
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

// probeTargetSlot is one node's permit semaphore plus the number of in-flight
// acquisitions (holders and waiters) that reference it. The reference count is
// what lets the slot table drop a node that is no longer being probed.
type probeTargetSlot struct {
	slots chan struct{}
	refs  int
}

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

// release undoes one reserve when the request never became a queued probe.
func (g *probeGate) release() {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.inFlight > 0 {
		g.inFlight--
	}
	g.mu.Unlock()
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

// acquireProbeTarget waits for one of the per-node slots that
// capabilities.probes.limits.max_concurrent_per_target advertises and returns
// its release. The permit is held for exactly one probe row, so the limit is
// per node and independent of which job (or how many jobs) is probing it. The
// map is keyed by node id and its entries are dropped once the last acquisition
// for a node finishes, so it stays proportional to the nodes being probed rather
// than to every node id the process has ever probed.
func (o *nativeAPIOperations) acquireProbeTarget(ctx context.Context, nodeID string) (func(), error) {
	o.probeTargetsMu.Lock()
	if o.probeTargetSlots == nil {
		o.probeTargetSlots = make(map[string]*probeTargetSlot)
	}
	entry := o.probeTargetSlots[nodeID]
	if entry == nil {
		entry = &probeTargetSlot{slots: make(chan struct{}, probeMaxActiveJobs)}
		o.probeTargetSlots[nodeID] = entry
	}
	// Count holders and waiters alike: the entry may only be dropped when no
	// acquisition can still reach it, or a waiter would be left on a channel
	// nobody else limits.
	entry.refs++
	o.probeTargetsMu.Unlock()

	select {
	case entry.slots <- struct{}{}:
	case <-ctx.Done():
		o.releaseProbeTarget(nodeID, entry)
		return nil, ctx.Err()
	}
	released := false
	return func() {
		if released {
			return
		}
		released = true
		<-entry.slots
		o.releaseProbeTarget(nodeID, entry)
	}, nil
}

// releaseProbeTarget drops one reference to a node's slot set and removes the
// map entry once the last one is gone.
func (o *nativeAPIOperations) releaseProbeTarget(nodeID string, entry *probeTargetSlot) {
	o.probeTargetsMu.Lock()
	defer o.probeTargetsMu.Unlock()
	entry.refs--
	if entry.refs > 0 {
		return
	}
	if current, ok := o.probeTargetSlots[nodeID]; ok && current == entry {
		delete(o.probeTargetSlots, nodeID)
	}
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
	// Reserve first: a probe refused by the gate or the rate limit must not
	// leave an operation record behind for the whole retention window.
	if err := o.probes.reserve(time.Now()); err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	accepted, replayed, err := o.store.Accept(nativeapi.OperationKindProbe, probeScope(request), idempotencyKey)
	if err != nil {
		o.probes.release()
		return nativeapi.OperationAccepted{}, err
	}
	if replayed {
		// The original request already queued this work.
		o.probes.release()
		return accepted, nil
	}
	// Reject oversized fan-out before any probe work runs. The contract asks
	// for 413 here, not a successful operation that silently drops the
	// dimensions beyond the result cap.
	if err := o.validateProbeFanout(request); err != nil {
		o.probes.release()
		o.store.ReleaseReplayKey(idempotencyKey)
		o.store.Fail(accepted.OperationID, safeProbeError(err))
		return nativeapi.OperationAccepted{}, err
	}
	// The work is queued, so the reserved key becomes replayable. Without this
	// a retry with the same key answered 409 until the process restarted.
	o.store.CommitReplayKey(idempotencyKey)
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
	ctx, cancel := context.WithTimeout(context.Background(), probeJobTimeout)
	defer cancel()
	soMark := plane.SoMarkFromDae()
	targets := probeTargetsFor(active, plane, request)
	ipVersions := []string{request.IPVersion}
	if request.IPVersion == "any" {
		// The contract advertises both families for `any`; a single IPv4 row
		// left the IPv6 dimension silently untested.
		ipVersions = []string{"ipv4", "ipv6"}
	}
	projected := len(members) * len(request.Transport) * len(ipVersions)
	if projected > probeMaxResultsPerJob {
		return nativeapi.ProbeResult{}, probeFanoutTooLarge(projected)
	}
	result := nativeapi.ProbeResult{
		Target:           request.Target,
		SelectionChanged: nativeapi.TransportBooleanMap{},
		SelectionBefore:  nativeapi.TransportSelectionMap{},
		SelectionAfter:   nativeapi.TransportSelectionMap{},
		Results:          make([]nativeapi.ProbeResultItem, projected),
	}
	// Run rows with the per-target concurrency the capabilities advertise
	// (`max_concurrent_per_target`). Sequential probing made a job with eight
	// dead endpoints run for the whole 30 s job deadline; four workers finish
	// the same rows in two per-row timeouts, while results keep the requested
	// member/transport/family order.
	type probeRow struct {
		index     int
		member    probeMember
		transport string
		ipVersion string
	}
	rows := make([]probeRow, 0, projected)
	for _, member := range members {
		for _, transport := range request.Transport {
			for _, ipVersion := range ipVersions {
				rows = append(rows, probeRow{index: len(rows), member: member, transport: transport, ipVersion: ipVersion})
			}
		}
	}
	workers := probeMaxActiveJobs
	if workers > len(rows) {
		workers = len(rows)
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, row := range rows {
		wg.Add(1)
		go func(row probeRow) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				result.Results[row.index] = probeUnavailableResult(row.member, request, row.transport, row.ipVersion, "probe job deadline exceeded")
				return
			}
			releaseTarget, err := o.acquireProbeTarget(ctx, row.member.id)
			if err != nil {
				result.Results[row.index] = probeUnavailableResult(row.member, request, row.transport, row.ipVersion, "probe job deadline exceeded")
				return
			}
			defer releaseTarget()
			result.Results[row.index] = runProbeMember(ctx, row.member, request, row.transport, row.ipVersion, soMark, plane.DirectDialer(), targets)
		}(row)
	}
	wg.Wait()
	return result, nil
}

// validateProbeFanout expands the target before the work is queued so an
// oversized request is rejected with 413 instead of producing an operation
// that silently omits the dimensions beyond the result cap.
func (o *nativeAPIOperations) validateProbeFanout(request nativeapi.ProbeRequest) error {
	if o == nil || o.supervisor == nil {
		return fmt.Errorf("no active runtime generation")
	}
	active := o.supervisor.activeSnapshot()
	if active == nil || active.controlPlane == nil {
		return fmt.Errorf("no active runtime generation")
	}
	members, err := probeMembers(active.controlPlane, request)
	if err != nil {
		// Keep the 422 a malformed member already carries; an unknown target
		// is a 404 instead of a provider-failure 503.
		var apiErr *nativeapi.APIError
		if errors.As(err, &apiErr) {
			return err
		}
		return nativeapi.NewAPIError(404, "resource_not_found", err.Error())
	}
	ipVersions := 1
	if request.IPVersion == "any" {
		ipVersions = 2
	}
	projected := len(members) * len(request.Transport) * ipVersions
	if projected > probeMaxResultsPerJob {
		return probeFanoutTooLarge(projected)
	}
	return nil
}

func probeFanoutTooLarge(projected int) error {
	return nativeapi.NewAPIError(413, "request_too_large",
		fmt.Sprintf("probe expands to %d results, more than this engine supports", projected))
}

func safeProbeError(err error) *nativeapi.SafeError {
	if err == nil {
		return nil
	}
	var apiErr *nativeapi.APIError
	if errors.As(err, &apiErr) {
		return &nativeapi.SafeError{Code: apiErr.Code, Message: apiErr.Message}
	}
	return &nativeapi.SafeError{Code: "probe_failed", Message: err.Error()}
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

	groupDialers := make(map[string][]*dialer.Dialer)
	for _, group := range plane.OutboundGroups() {
		if group == nil {
			continue
		}
		groupDialers[groupIDOf(group.Name)] = group.Dialers
	}
	targetGroupID := request.Target.GroupID
	targetDialers, ok := groupDialers[targetGroupID]
	if !ok {
		return nil, fmt.Errorf("group not found")
	}
	targetByID := make(map[string]*dialer.Dialer, len(targetDialers))
	for _, item := range targetDialers {
		if property := item.Property(); property != nil {
			targetByID[nodeIDOf(property)] = item
		}
	}

	var selected []string
	if request.Members == nil || len(request.Members.Values) == 0 {
		selected = append(selected, targetGroupID)
	} else {
		selected = append(selected, request.Members.Values...)
	}

	seen := map[string]struct{}{}
	members := make([]probeMember, 0, len(selected))
	addDialers := func() {
		for _, item := range targetDialers {
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
		// `direct`/`leaves` and the target group itself select its whole
		// direct-member set. Any other value must be one of those members; a
		// node or group from another group is not a valid member of this one.
		if value == targetGroupID || value == "direct" || value == "leaves" {
			addDialers()
			continue
		}
		item, ok := targetByID[value]
		if !ok {
			return nil, nativeapi.NewAPIError(422, "invalid_request", "member "+value+" is not a direct member of the target group")
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		members = append(members, probeMember{id: value, dialer: item})
	}
	sort.Slice(members, func(i, j int) bool { return members[i].id < members[j].id })
	if len(members) > probeMaxMembersPerJob {
		return nil, nativeapi.NewAPIError(422, "invalid_request", "probe expands to more members than this engine supports")
	}
	return members, nil
}

func probeUnavailableResult(member probeMember, request nativeapi.ProbeRequest, transport, ipVersion, reason string) nativeapi.ProbeResultItem {
	purpose := "data"
	if request.Kind == "dns" {
		purpose = "dns"
	}
	return nativeapi.ProbeResultItem{
		MemberID:      member.id,
		Kind:          request.Kind,
		Purpose:       purpose,
		Transport:     transport,
		IPVersion:     ipVersion,
		Warmth:        "unknown",
		State:         "unknown",
		HealthUpdated: false,
		Error:         &reason,
		ObservedAt:    time.Now().UTC().Format(time.RFC3339),
	}
}

func runProbeMember(parent context.Context, member probeMember, request nativeapi.ProbeRequest, transport, ipVersion string, soMark uint32, direct netproxy.Dialer, targets probeCheckTargets) nativeapi.ProbeResultItem {
	purpose := "data"
	if request.Kind == "dns" {
		purpose = "dns"
	}
	item := nativeapi.ProbeResultItem{
		MemberID:  member.id,
		Kind:      request.Kind,
		Purpose:   purpose,
		Transport: transport,
		IPVersion: ipVersion,
		// The engine opens a fresh logical connection per probe and does not
		// track physical tunnel reuse, so it must not claim either "cold"
		// (a new stream does not prove a cold tunnel) or the requested "warm".
		Warmth:        "unknown",
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
	ctx, cancel := context.WithTimeout(parent, probeTimeout)
	defer cancel()

	// Deadlines alone do not bound a probe: the pinned HTTP/2 transport
	// implements SetDeadline as a no-op, and a peer that never answers would
	// then hold one of the few probe slots for good. Every connection a probe
	// opens is registered here and closed when the context ends.
	conns := &probeConnRegistry{}
	go func() {
		<-ctx.Done()
		conns.closeAll()
	}()

	var (
		err     error
		elapsed time.Duration
	)
	switch request.Kind {
	case "tcp_connect":
		// Report what the probe claims to test: whether the node's own server
		// accepts a TCP connection in the requested address family. Dialling
		// 1.1.1.1 through the proxy measured the far side's reachability
		// instead, so a working node answered unavailable whenever the exit
		// could not reach that address.
		address, addressErr := probeNodeAddressForFamily(ctx, member.dialer, item.IPVersion)
		switch {
		case addressErr != nil:
			err = addressErr
		case address == "":
			// A node without a server address (the builtin direct outbound) has
			// no server to connect to, so fall back to a dial through the node.
			address = probeDialAddress("tcp", item.IPVersion)
			elapsed, err = dialAndClose(ctx, conns, member.dialer, soMark, "tcp", address)
		default:
			elapsed, err = dialAndClose(ctx, conns, direct, soMark, "tcp", address)
		}
	case "http":
		elapsed, err = probeHTTP(ctx, conns, member.dialer, soMark, item.IPVersion, targets)
	case "dns":
		elapsed, err = probeDNS(ctx, conns, member.dialer, soMark, item.IPVersion, transport, targets)
	default:
		item.State = "unavailable"
		reason := fmt.Sprintf("probe kind %q is not supported", request.Kind)
		item.Error = &reason
		return item
	}
	if err != nil {
		// A row the 30 s job deadline cancels never produced evidence about the
		// node. The contract reports such work as `unknown`; only a probe that
		// ran to completion with a failure is `unavailable`.
		if parent.Err() != nil {
			return probeUnavailableResult(member, request, transport, ipVersion, "probe job deadline exceeded")
		}
		item.State = "unavailable"
		reason := sanitizeLogMessage(err.Error())
		item.Error = &reason
		return item
	}
	latency := float64(elapsed.Microseconds()) / 1000
	item.State = "healthy"
	item.LatencyMs = &latency
	return item
}

// probeCheckTargets are the administrator-configured destinations for the
// HTTP and DNS probes. A probe must exercise the same check URL / DNS target
// the engine uses for health, not a hard-coded public endpoint. The lists keep
// their full form - first entry is the URL / resolver, the rest are the literal
// address overrides the health check dials - because dropping the overrides sent
// the probe's host through the system resolver instead of the configured IP.
type probeCheckTargets struct {
	http       []string
	httpMethod string
	dns        []string
}

func probeTargetsFor(active *runtimeGeneration, plane *control.ControlPlane, request nativeapi.ProbeRequest) probeCheckTargets {
	group := probeGroupFor(active, plane, request)
	targets := probeCheckTargets{}
	if group != nil {
		targets.httpMethod = group.TcpCheckHttpMethod
		targets.http = append([]string(nil), group.TcpCheckUrl...)
		targets.dns = append([]string(nil), group.UdpCheckDns...)
	}
	// A group only carries the values it overrides. The administrator normally
	// sets tcp_check_url / udp_check_dns / tcp_check_http_method in `global`,
	// and the dialer health checks inherit them from there. Falling back to the
	// hard-coded public endpoints made http/dns probes ignore that
	// configuration (including the HEAD method) whenever the group had no
	// override of its own.
	if active != nil && active.conf != nil {
		if len(targets.http) == 0 && len(active.conf.Global.TcpCheckUrl) > 0 {
			targets.http = append([]string(nil), active.conf.Global.TcpCheckUrl...)
		}
		if targets.httpMethod == "" {
			targets.httpMethod = active.conf.Global.TcpCheckHttpMethod
		}
		if len(targets.dns) == 0 && len(active.conf.Global.UdpCheckDns) > 0 {
			targets.dns = append([]string(nil), active.conf.Global.UdpCheckDns...)
		}
	}
	return targets
}

func probeGroupFor(active *runtimeGeneration, plane *control.ControlPlane, request nativeapi.ProbeRequest) *config.Group {
	if active == nil || active.conf == nil {
		return nil
	}
	byName := func(name string) *config.Group {
		for i := range active.conf.Group {
			if active.conf.Group[i].Name == name {
				return &active.conf.Group[i]
			}
		}
		return nil
	}
	if request.Target.Type == "group" {
		for i := range active.conf.Group {
			if groupIDOf(active.conf.Group[i].Name) == request.Target.GroupID {
				return &active.conf.Group[i]
			}
		}
		return nil
	}
	if request.Target.Type == "node" && plane != nil {
		for _, group := range plane.OutboundGroups() {
			if group == nil {
				continue
			}
			for _, item := range group.Dialers {
				if property := item.Property(); property != nil && nodeIDOf(property) == request.Target.NodeID {
					return byName(group.Name)
				}
			}
		}
	}
	return nil
}

func probeDNSHostPort(raw string) string {
	raw = strings.TrimSpace(raw)
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		raw = u.Host
	}
	if _, _, err := net.SplitHostPort(raw); err != nil {
		return net.JoinHostPort(raw, "53")
	}
	return raw
}

// probeCheckIPOverride returns the literal address the health check would dial
// for the requested family, or "" when the check list declares no override for
// it. tcp_check_url and udp_check_dns keep the destination first and the
// overrides after it (see parseTcpCheckOption / parseCheckDNSOption); the
// probes have to honour the same entries or a configured IP is replaced by a
// system-resolver lookup.
func probeCheckIPOverride(raw []string, ipVersion string) string {
	// Index from 1 instead of slicing raw[1:]: an unconfigured check list is
	// nil/empty, and slicing it at 1 panics. A list with only the destination
	// simply has no override.
	for i := 1; i < len(raw); i++ {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw[i]))
		if err != nil {
			continue
		}
		// Match parseIp46FromList: a 4-in-6 literal is an IPv4 override.
		is4 := addr.Is4() || addr.Is4In6()
		if is4 == (ipVersion == "ipv6") {
			continue
		}
		return addr.String()
	}
	return ""
}

// probeNodeAddressForFamily is probeNodeAddress with the requested address
// family enforced. A tcp_connect request labelled ipv6 must not silently
// connect to an IPv4 listener and report healthy.
func probeNodeAddressForFamily(ctx context.Context, d *dialer.Dialer, ipVersion string) (string, error) {
	if d == nil {
		return "", fmt.Errorf("dialer is unavailable")
	}
	property := d.Property()
	if property == nil {
		return "", fmt.Errorf("dialer has no address")
	}
	host, port, err := net.SplitHostPort(property.Address)
	if err != nil || host == "" || port == "" {
		return "", nil
	}
	if ip := net.ParseIP(host); ip != nil {
		isIPv6 := ip.To4() == nil
		if (ipVersion == "ipv6") != isIPv6 {
			return "", fmt.Errorf("node server has no %s address", ipVersion)
		}
		return property.Address, nil
	}
	network := "ip4"
	if ipVersion == "ipv6" {
		network = "ip6"
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, network, host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("node server has no %s address", ipVersion)
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}

// probeAddressForFamily resolves a check destination to the requested address
// family. A literal address of the other family is rejected instead of being
// dialled, and a hostname is resolved through the matching family resolver.
// The http and dns probes used to dial whatever the platform resolver returned,
// so an ipv6 probe could pass by reaching an IPv4 listener.
func probeAddressForFamily(ctx context.Context, address, ipVersion string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); ip != nil {
		isIPv6 := ip.To4() == nil
		if (ipVersion == "ipv6") != isIPv6 {
			return "", fmt.Errorf("check destination has no %s address", ipVersion)
		}
		return address, nil
	}
	network := "ip4"
	if ipVersion == "ipv6" {
		network = "ip6"
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, network, host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("check destination has no %s address", ipVersion)
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}

// probeNodeAddress returns the node's own server address, which is what a
// tcp_connect probe has to reach. It is empty for outbounds without a server.
func probeNodeAddress(d *dialer.Dialer) string {
	if d == nil {
		return ""
	}
	property := d.Property()
	if property == nil {
		return ""
	}
	host, port, err := net.SplitHostPort(property.Address)
	if err != nil || host == "" || port == "" {
		return ""
	}
	return property.Address
}

// probeDialAddress is the well-known endpoint a dial probe reaches through the
// node. It answers on 443, which is what an http probe talks to.
func probeDialAddress(network, ipVersion string) string {
	if ipVersion == "ipv6" {
		if network == "udp" {
			return "[2606:4700:4700::1111]:53"
		}
		return "[2606:4700:4700::1111]:443"
	}
	if network == "udp" {
		return "1.1.1.1:53"
	}
	return "1.1.1.1:443"
}

// probeDNSAddress is the resolver a DNS probe sends its query to. A DNS probe
// speaks DNS on both transports; the port does not follow the transport, so
// reusing probeDialAddress sent length-prefixed DNS frames to port 443.
func probeDNSAddress(ipVersion string) string {
	if ipVersion == "ipv6" {
		return "[2606:4700:4700::1111]:53"
	}
	return "1.1.1.1:53"
}

// probeConnRegistry tracks the connections one probe opened, so the context
// watcher can interrupt a read that ignores deadlines.
type probeConnRegistry struct {
	mu    sync.Mutex
	conns []io.Closer
}

func (r *probeConnRegistry) add(closer io.Closer) {
	if r == nil || closer == nil {
		return
	}
	r.mu.Lock()
	r.conns = append(r.conns, closer)
	r.mu.Unlock()
}

func (r *probeConnRegistry) closeAll() {
	if r == nil {
		return
	}
	r.mu.Lock()
	conns := r.conns
	r.conns = nil
	r.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func dialAndClose(ctx context.Context, conns *probeConnRegistry, d netproxy.Dialer, soMark uint32, network, address string) (time.Duration, error) {
	if d == nil {
		return 0, fmt.Errorf("dialer is unavailable")
	}
	started := time.Now()
	conn, err := d.DialContext(ctx, common.MagicNetwork(network, soMark, false), address)
	elapsed := time.Since(started)
	if err != nil {
		return 0, err
	}
	if conn != nil {
		_ = conn.Close()
	}
	return elapsed, nil
}

// probeHTTP sends a real request through the node and requires a real response.
// A bare TCP dial never proved the node forwards traffic.
func probeHTTP(ctx context.Context, conns *probeConnRegistry, d *dialer.Dialer, soMark uint32, ipVersion string, targets probeCheckTargets) (time.Duration, error) {
	target := ""
	if len(targets.http) > 0 {
		target = strings.TrimSpace(targets.http[0])
	}
	if target == "" {
		host := "1.1.1.1"
		if ipVersion == "ipv6" {
			host = "[2606:4700:4700::1111]"
		}
		target = "http://" + host + "/"
	} else if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	method := targets.httpMethod
	if method == "" {
		method = http.MethodGet
	}
	// The request keeps the configured host - Host and TLS SNI must stay the
	// administrator's name - while the dial uses the health check's literal
	// override when one is configured for the family.
	checkHost := ""
	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, splitErr := net.SplitHostPort(address)
		if splitErr == nil && strings.EqualFold(host, checkHost) {
			if ip := probeCheckIPOverride(targets.http, ipVersion); ip != "" {
				address = net.JoinHostPort(ip, port)
			}
		}
		address, err := probeAddressForFamily(ctx, address, ipVersion)
		if err != nil {
			return nil, err
		}
		conn, err := d.DialContext(ctx, common.MagicNetwork(network, soMark, false), address)
		if err != nil {
			return nil, err
		}
		wrapped := &netproxy.FakeNetConn{Conn: conn}
		conns.add(wrapped)
		return wrapped, nil
	}
	client := &http.Client{
		Transport: &http.Transport{DialContext: dialContext, DisableKeepAlives: true},
		Timeout:   probeTimeout,
	}
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return 0, err
	}
	checkHost = req.URL.Hostname()
	req.Header.Set("User-Agent", "dae-probe/1.0")
	started := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(started)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 500 {
		return 0, fmt.Errorf("http probe answered %d", resp.StatusCode)
	}
	return elapsed, nil
}

// probeDNS sends a real DNS query through the node and requires an answer to
// that query, not merely any DNS-shaped packet.
func probeDNS(ctx context.Context, conns *probeConnRegistry, d *dialer.Dialer, soMark uint32, ipVersion, transport string, targets probeCheckTargets) (time.Duration, error) {
	network := "udp"
	if transport == "tcp" {
		network = "tcp"
	}
	// udp_check_dns lists the resolver first and literal overrides after it.
	// The override is what the health check dials, so send the query there
	// instead of resolving the configured host through the system resolver.
	address := ""
	if len(targets.dns) > 0 {
		address = probeDNSHostPort(targets.dns[0])
	}
	if ip := probeCheckIPOverride(targets.dns, ipVersion); ip != "" {
		port := "53"
		if _, configuredPort, splitErr := net.SplitHostPort(address); splitErr == nil {
			port = configuredPort
		}
		address = net.JoinHostPort(ip, port)
	}
	if address == "" {
		address = probeDNSAddress(ipVersion)
	}
	address, err := probeAddressForFamily(ctx, address, ipVersion)
	if err != nil {
		return 0, err
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return 0, err
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("example.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return 0, err
	}
	query, err := builder.Finish()
	if err != nil {
		return 0, err
	}
	started := time.Now()
	conn, err := d.DialContext(ctx, common.MagicNetwork(network, soMark, false), address)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()
	conns.add(conn)
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if network == "tcp" {
		if err := writeDNSOverTCP(conn, query); err != nil {
			return 0, err
		}
		reply, err := readDNSOverTCP(conn)
		if err != nil {
			return 0, err
		}
		return parseDNSReply(reply, query, time.Since(started))
	}
	if _, err := conn.Write(query); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, err
	}
	return parseDNSReply(buf[:n], query, time.Since(started))
}

func writeDNSOverTCP(conn io.Writer, query []byte) error {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(query)))
	if _, err := conn.Write(append(length, query...)); err != nil {
		return err
	}
	return nil
}

func readDNSOverTCP(conn io.Reader) ([]byte, error) {
	length := make([]byte, 2)
	if _, err := io.ReadFull(conn, length); err != nil {
		return nil, err
	}
	reply := make([]byte, binary.BigEndian.Uint16(length))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// parseDNSReply requires the answer to echo the transaction ID and the question
// of the request. A header-only reply, or one carrying another question, came
// from a different exchange and must not pass for a healthy DNS probe.
func parseDNSReply(reply []byte, query []byte, elapsed time.Duration) (time.Duration, error) {
	var queryParser dnsmessage.Parser
	queryHeader, queryErr := queryParser.Start(query)
	if queryErr != nil {
		return 0, fmt.Errorf("dns probe query is malformed")
	}
	queryQuestion, queryErr := queryParser.Question()
	if queryErr != nil {
		return 0, fmt.Errorf("dns probe query carries no question")
	}

	var parser dnsmessage.Parser
	header, err := parser.Start(reply)
	if err != nil {
		return 0, fmt.Errorf("dns probe reply is malformed")
	}
	if !header.Response {
		return 0, fmt.Errorf("dns probe reply is not a response")
	}
	if header.ID != queryHeader.ID {
		return 0, fmt.Errorf("dns probe reply carries transaction ID %d, want %d", header.ID, queryHeader.ID)
	}
	replyQuestions, err := parser.AllQuestions()
	if err != nil {
		return 0, fmt.Errorf("dns probe reply carries no question")
	}
	if len(replyQuestions) != 1 || replyQuestions[0] != queryQuestion {
		if len(replyQuestions) != 1 {
			return 0, fmt.Errorf("dns probe reply carries %d questions, want 1", len(replyQuestions))
		}
		replyQuestion := replyQuestions[0]
		return 0, fmt.Errorf("dns probe reply answers %s/%d, want %s/%d",
			replyQuestion.Name.String(), replyQuestion.Type, queryQuestion.Name.String(), queryQuestion.Type)
	}
	// Parse every section a DNS message declares. Reading only the question
	// let a header with ANCOUNT=1 and no answer bytes pass as healthy; a
	// truncated authority/additional section was accepted for the same reason.
	if _, err := parser.AllAnswers(); err != nil && !errors.Is(err, dnsmessage.ErrSectionDone) {
		return 0, fmt.Errorf("dns probe reply has an incomplete answer section")
	}
	if _, err := parser.AllAuthorities(); err != nil && !errors.Is(err, dnsmessage.ErrSectionDone) {
		return 0, fmt.Errorf("dns probe reply has an incomplete authority section")
	}
	if _, err := parser.AllAdditionals(); err != nil && !errors.Is(err, dnsmessage.ErrSectionDone) {
		return 0, fmt.Errorf("dns probe reply has an incomplete additional section")
	}
	return elapsed, nil
}

var _ nativeapi.ProbeProvider = (*nativeAPIOperations)(nil)

// probeScope identifies one probe request for the idempotency check, so a key
// reused for a different target or transport is a conflict instead of a replay.
func probeScope(request nativeapi.ProbeRequest) string {
	target := request.Target.Type + ":" + request.Target.NodeID + ":" + request.Target.GroupID
	if request.Members != nil {
		target += fmt.Sprint(request.Members.Values)
	}
	return request.Kind + "\x00" + target + "\x00" + strings.Join(request.Transport, ",") + "\x00" + request.IPVersion + "\x00" + request.Warmth
}
