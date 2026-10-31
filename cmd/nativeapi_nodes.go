/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"encoding/base64"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

// healthSample is one collection's health plus the latency metrics a group may
// sort by.
type healthSample struct {
	observation nativeapi.HealthObservation
	lastMs      *float64
	avg10Ms     *float64
	movingAvgMs *float64
}

// dialerHealthSamples projects a dialer's probe state into contract
// observations. Collections that were never probed are omitted rather than
// reported with fabricated timestamps.
func dialerHealthSamples(d *dialer.Dialer) []healthSample {
	if d == nil {
		return nil
	}
	snapshot := d.HealthSnapshot()
	keys := dialer.StandardHealthKeys()
	samples := make([]healthSample, 0, len(keys))
	for _, key := range keys {
		collection := snapshot.Collections[key.CollectionIndex()]
		probe := collection.LastProbe
		if probe.CheckedAt.IsZero() {
			continue
		}
		transport, purpose := healthDomainOf(key.Domain)
		state := "unavailable"
		var probeError *string
		if probe.Alive {
			state = "healthy"
		} else {
			// Keep engine detail out of the response: the contract wants a
			// stable, sanitized reason.
			reason := "probe_failed"
			probeError = &reason
		}
		lastMs := durationToMs(probe.Latency, probe.HasLatency)
		avg10Ms := averageLatencyMs(collection.Latencies)
		movingAvgMs := durationToMs(collection.MovingAverage, collection.MovingAverage > 0)
		measurement := "http_headers"
		if transport == "udp" {
			measurement = "dns_round_trip"
		}
		samples = append(samples, healthSample{
			observation: nativeapi.HealthObservation{
				Transport:    transport,
				Purpose:      purpose,
				IpVersion:    ipVersionName(key.IpVersion),
				Warmth:       "unknown",
				Measurement:  measurement,
				SampleSource: "probe",
				State:        state,
				LatencyMs:    lastMs,
				MovingAvgMs:  movingAvgMs,
				Avg10Ms:      avg10Ms,
				ObservedAt:   probe.CheckedAt.UTC().Format(time.RFC3339),
				Error:        probeError,
			},
			lastMs:      lastMs,
			avg10Ms:     avg10Ms,
			movingAvgMs: movingAvgMs,
		})
	}
	return samples
}

func healthDomainOf(domain dialer.HealthDomain) (transport, purpose string) {
	switch domain {
	case dialer.HealthDomainTCP:
		return "tcp", "shared"
	case dialer.HealthDomainDnsUDP:
		return "udp", "dns"
	case dialer.HealthDomainDataUDP:
		return "udp", "data"
	default:
		return "tcp", "shared"
	}
}

func ipVersionName(version consts.IpVersionStr) string {
	if version == consts.IpVersionStr_6 {
		return "ipv6"
	}
	return "ipv4"
}

func durationToMs(value time.Duration, ok bool) *float64 {
	if !ok {
		return nil
	}
	ms := float64(value) / float64(time.Millisecond)
	return &ms
}

func averageLatencyMs(snapshot dialer.LatenciesNSnapshot) *float64 {
	if len(snapshot.Latencies) == 0 {
		return nil
	}
	ms := float64(snapshot.SumNLatencies) / float64(len(snapshot.Latencies)) / float64(time.Millisecond)
	return &ms
}

// sortingLatency picks the metric the group's policy ranks members by.
func sortingLatency(policy consts.DialerSelectionPolicy, sample healthSample) *float64 {
	switch policy {
	case consts.DialerSelectionPolicy_MinLastLatency:
		return sample.lastMs
	case consts.DialerSelectionPolicy_MinAverage10Latencies:
		return sample.avg10Ms
	case consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		return sample.movingAvgMs
	default:
		return nil
	}
}

func dialerHealthObservations(d *dialer.Dialer) []nativeapi.HealthObservation {
	samples := dialerHealthSamples(d)
	observations := make([]nativeapi.HealthObservation, 0, len(samples))
	for _, sample := range samples {
		observations = append(observations, sample.observation)
	}
	return observations
}

func groupMemberHealth(item userGroup) []nativeapi.GroupHealthObservation {
	// Health follows the same member identity the group resource reports: two
	// dialers carrying one share link are one member, so their samples merge
	// instead of appearing twice under the same key.
	memberOrder := make([]string, 0, len(item.group.Dialers))
	memberSamples := make(map[string][]healthSample, len(item.group.Dialers))
	for _, d := range item.group.Dialers {
		property := d.Property()
		if property == nil {
			continue
		}
		memberID := nodeIDOf(property)
		if _, seen := memberSamples[memberID]; !seen {
			memberOrder = append(memberOrder, memberID)
		}
		memberSamples[memberID] = mergeHealthSamples(memberSamples[memberID], dialerHealthSamples(d))
	}

	observations := make([]nativeapi.GroupHealthObservation, 0, len(memberOrder)*2)
	for _, memberID := range memberOrder {
		for _, sample := range memberSamples[memberID] {
			observations = append(observations, nativeapi.GroupHealthObservation{
				HealthObservation: sample.observation,
				MemberID:          memberID,
				SortingLatencyMs:  sortingLatency(item.policy.Policy, sample),
			})
		}
	}
	return observations
}

// mergeHealthSamples keeps one sample per transport/purpose/IP version,
// preferring the most recent observation.
func mergeHealthSamples(existing []healthSample, incoming []healthSample) []healthSample {
	if len(incoming) == 0 {
		return existing
	}
	index := make(map[string]int, len(existing))
	for i, sample := range existing {
		index[healthObservationKey(sample.observation)] = i
	}
	for _, sample := range incoming {
		key := healthObservationKey(sample.observation)
		if i, ok := index[key]; ok {
			if observationIsNewer(sample.observation, existing[i].observation) {
				existing[i] = sample
			}
			continue
		}
		index[key] = len(existing)
		existing = append(existing, sample)
	}
	return existing
}

// nodeCursor binds a page walk to one generation, so a reload invalidates it
// instead of silently paginating a different inventory.
type nodeCursor struct {
	generation string
	offset     int
}

func encodeNodeCursor(cursor nodeCursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(cursor.generation + ":" + strconv.Itoa(cursor.offset)))
}

func decodeNodeCursor(raw string) (nodeCursor, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nodeCursor{}, false
	}
	separator := strings.LastIndex(string(decoded), ":")
	if separator <= 0 {
		return nodeCursor{}, false
	}
	offset, err := strconv.Atoi(string(decoded)[separator+1:])
	if err != nil || offset < 0 {
		return nodeCursor{}, false
	}
	return nodeCursor{generation: string(decoded)[:separator], offset: offset}, true
}

func (p *nativeAPIProvider) ListNodes(ctx context.Context, groupID string, limit int, cursor string) (nativeapi.NodeList, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.NodeList{}, err
	}
	active, err := p.activeGeneration()
	if err != nil {
		return nativeapi.NodeList{}, err
	}
	nodes, err := active.nodes(groupID)
	if err != nil {
		return nativeapi.NodeList{}, err
	}
	offset := 0
	if cursor != "" {
		decoded, ok := decodeNodeCursor(cursor)
		if !ok || decoded.generation != active.generation.id || decoded.offset > len(nodes) {
			return nativeapi.NodeList{}, nativeapi.NewAPIError(410, "snapshot_expired", "cursor does not belong to the current node snapshot")
		}
		offset = decoded.offset
	}
	end := offset + limit
	if end > len(nodes) {
		end = len(nodes)
	}
	page := nativeapi.NodeList{
		ObservedAt: time.Now().UTC().Format(time.RFC3339),
		Nodes:      nodes[offset:end],
	}
	if end < len(nodes) {
		next := encodeNodeCursor(nodeCursor{generation: active.generation.id, offset: end})
		page.NextCursor = &next
	}
	return page, nil
}

func (p *nativeAPIProvider) GetNode(ctx context.Context, nodeID string) (*nativeapi.Node, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	active, err := p.activeGeneration()
	if err != nil {
		return nil, err
	}
	nodes, err := active.nodes("")
	if err != nil {
		return nil, err
	}
	for i := range nodes {
		if nodes[i].ID == nodeID {
			node := nodes[i]
			return &node, nil
		}
	}
	return nil, nativeapi.NewAPIError(404, "resource_not_found", "node not found")
}

// nodes projects the managed dialers, optionally limited to one group.
func (a *nativeActiveGeneration) nodes(groupID string) ([]nativeapi.Node, error) {
	groups := a.userGroups()
	if groupID != "" {
		if _, ok := a.findGroup(groupID); !ok {
			return nil, nativeapi.NewAPIError(404, "resource_not_found", "group not found")
		}
	}
	groupIDs := make(map[*dialer.Dialer][]string, len(a.groups))
	for _, item := range groups {
		id := groupIDOf(item.group.Name)
		if groupID != "" && id != groupID {
			continue
		}
		for _, d := range item.group.Dialers {
			groupIDs[d] = append(groupIDs[d], id)
		}
	}

	// The builtin direct/block dialers are engine pseudo-nodes, not user nodes.
	builtin := make(map[*dialer.Dialer]struct{}, 2)
	for _, group := range a.groups {
		if group == nil {
			continue
		}
		switch group.Name {
		case consts.OutboundDirect.String(), consts.OutboundBlock.String():
			for _, d := range group.Dialers {
				builtin[d] = struct{}{}
			}
		}
	}

	all := a.generation.controlPlane.EgressDialers()
	nodes := make([]nativeapi.Node, 0, len(all))
	indexByID := make(map[string]int, len(all))
	for _, d := range all {
		if _, isBuiltin := builtin[d]; isBuiltin {
			continue
		}
		ids, inGroup := groupIDs[d]
		if groupID != "" && !inGroup {
			continue
		}
		property := d.Property()
		if property == nil {
			continue
		}
		id := nodeIDOf(property)
		health := dialerHealthObservations(d)
		if existing, ok := indexByID[id]; ok {
			// The node ID is derived from the share link, so two
			// subscriptions carrying the same link are one node. Merge their
			// memberships and health instead of returning duplicate IDs.
			node := &nodes[existing]
			node.GroupIDs = mergeSortedStrings(node.GroupIDs, ids)
			node.Health = mergeHealthObservations(node.Health, health)
			continue
		}
		indexByID[id] = len(nodes)
		node := nativeapi.Node{
			ID:              id,
			Name:            property.Name,
			Protocol:        optionalString(property.Protocol),
			SubscriptionTag: optionalString(property.SubscriptionTag),
			ProviderID:      stringPointer(providerIDOf(property.SubscriptionTag)),
			GroupIDs:        mergeSortedStrings(nil, ids),
			Health:          health,
		}
		if node.Health == nil {
			node.Health = []nativeapi.HealthObservation{}
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func mergeSortedStrings(existing []string, additional []string) []string {
	if len(additional) == 0 {
		if existing == nil {
			return []string{}
		}
		return existing
	}
	merged := append(append([]string{}, existing...), additional...)
	sort.Strings(merged)
	unique := merged[:0]
	for _, value := range merged {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return unique
}

func healthObservationKey(observation nativeapi.HealthObservation) string {
	return observation.Transport + "\x00" + observation.Purpose + "\x00" + observation.IpVersion
}

// mergeHealthObservations keeps one observation per transport/purpose/IP
// version, preferring the most recently probed one.
func mergeHealthObservations(existing []nativeapi.HealthObservation, incoming []nativeapi.HealthObservation) []nativeapi.HealthObservation {
	if len(incoming) == 0 {
		return existing
	}
	index := make(map[string]int, len(existing))
	for i, observation := range existing {
		index[healthObservationKey(observation)] = i
	}
	for _, observation := range incoming {
		key := healthObservationKey(observation)
		if i, ok := index[key]; ok {
			if observationIsNewer(observation, existing[i]) {
				existing[i] = observation
			}
			continue
		}
		index[key] = len(existing)
		existing = append(existing, observation)
	}
	return existing
}

func observationIsNewer(candidate, current nativeapi.HealthObservation) bool {
	candidateAt, err := time.Parse(time.RFC3339, candidate.ObservedAt)
	if err != nil {
		return false
	}
	currentAt, err := time.Parse(time.RFC3339, current.ObservedAt)
	if err != nil {
		return true
	}
	return candidateAt.After(currentAt)
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
