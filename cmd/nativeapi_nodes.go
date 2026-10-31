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

	// Engine-side ranking, filled only for the group projection. sortingMs is
	// the value the alive set actually compares (metric + recovery penalty +
	// manual offset), rank is its 1-based position, and deltaToBestMs is how far
	// it sits behind the best member of the same key.
	sortingMs   *float64
	offsetMs    *float64
	penaltyMs   *float64
	rank        *int
	deltaToBest *float64
}

// rankOfHealthKey resolves one dialer's engine-side rank for one health key.
type rankOfHealthKey func(*dialer.Dialer, dialer.HealthKey) (dialer.LatencyRank, bool)

// dialerHealthSamples projects a dialer's probe state into contract
// observations. Collections that were never probed are omitted rather than
// reported with fabricated timestamps, except data-UDP, which the engine ranks
// through its DNS sibling (see snapshotLatencyForPolicy).
func dialerHealthSamples(d *dialer.Dialer, rankOf rankOfHealthKey) []healthSample {
	if d == nil {
		return nil
	}
	snapshot := d.HealthSnapshot()
	keys := dialer.StandardHealthKeys()
	samples := make([]healthSample, 0, len(keys))
	// Data-UDP borrows the DNS sample of the same IP version, which the loop has
	// already produced: StandardHealthKeys lists the DNS keys first.
	byKey := make(map[dialer.HealthKey]healthSample, len(keys))
	for _, key := range keys {
		collection := snapshot.Collections[key.CollectionIndex()]
		probe := collection.LastProbe

		var sample healthSample
		if probe.CheckedAt.IsZero() {
			if key.Domain != dialer.HealthDomainDataUDP {
				continue
			}
			// Data-UDP has no probe of its own: real UDP traffic only flips the
			// alive flag and never records a delay, so the engine ranks it with
			// the DNS-UDP samples of the same dialer. Mirror that borrowing here
			// instead of dropping the key, which is what left the API with four
			// samples per node while the alive sets logged six networks.
			dnsKey := dialer.HealthKey{Domain: dialer.HealthDomainDnsUDP, IpVersion: key.IpVersion}
			borrowed, ok := byKey[dnsKey]
			if !ok || borrowed.observation.ObservedAt == "" {
				continue
			}
			sample = borrowed
			transport, purpose := healthDomainOf(key.Domain)
			sample.observation.Transport = transport
			sample.observation.Purpose = purpose
			sample.sortingMs, sample.offsetMs, sample.penaltyMs = nil, nil, nil
			sample.rank, sample.deltaToBest = nil, nil
		} else {
			sample = buildHealthSample(key, probe, collection)
		}

		if rankOf != nil {
			attachRank(&sample, d, key, rankOf)
		}
		byKey[key] = sample
		samples = append(samples, sample)
	}
	return samples
}

// buildHealthSample turns one collection's last probe into a contract
// observation.
func buildHealthSample(key dialer.HealthKey, probe dialer.DialerProbeObservationSnapshot, collection dialer.DialerCollectionHealthSnapshot) healthSample {
	transport, purpose := healthDomainOf(key.Domain)
	state := "unavailable"
	var probeError *string
	if probe.Alive {
		state = "healthy"
	} else {
		// Keep engine detail out of the response: the contract wants a stable,
		// sanitized reason.
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
	return healthSample{
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
	}
}

// attachRank copies the alive set's ordering for this dialer and key, so the
// API reports the value the engine compares rather than a re-derived metric.
func attachRank(sample *healthSample, d *dialer.Dialer, key dialer.HealthKey, rankOf rankOfHealthKey) {
	rank, ok := rankOf(d, key)
	if !ok || rank.Dialer != d {
		return
	}
	sortingMs := float64(rank.Sorting) / float64(time.Millisecond)
	offsetMs := float64(rank.Offset) / float64(time.Millisecond)
	rankNo := rank.Rank
	sample.sortingMs = &sortingMs
	sample.offsetMs = &offsetMs
	sample.rank = &rankNo
}

// healthDomainOf maps a health domain to the contract's transport/purpose pair.
//
// The purpose names what the latency is used for, not which probe produced it:
// TCP and data-UDP both carry "data", DNS carries "dns". Emitting "shared" for
// TCP (as this used to) put every node in a bucket no client recognises: the
// dashboard picks its primary latency from transport=tcp,purpose=data, found
// none, and reported every member as untested with zero available.
func healthDomainOf(domain dialer.HealthDomain) (transport, purpose string) {
	switch domain {
	case dialer.HealthDomainTCP:
		return "tcp", "data"
	case dialer.HealthDomainDnsUDP:
		return "udp", "dns"
	case dialer.HealthDomainDataUDP:
		return "udp", "data"
	default:
		return "tcp", "data"
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
	// The node resource is group-agnostic, so it has no alive set to rank by.
	samples := dialerHealthSamples(d, nil)
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

	// Snapshot each alive set once per key instead of once per member sample.
	ranksByKey := make(map[int]map[*dialer.Dialer]dialer.LatencyRank, 6)
	rankOf := func(d *dialer.Dialer, key dialer.HealthKey) (dialer.LatencyRank, bool) {
		idx := key.CollectionIndex()
		ranks, ok := ranksByKey[idx]
		if !ok {
			ranks = make(map[*dialer.Dialer]dialer.LatencyRank)
			if set := item.group.MustGetAliveDialerSet(key.NetworkType()); set != nil {
				for _, rank := range set.SortingSnapshot() {
					ranks[rank.Dialer] = rank
				}
			}
			ranksByKey[idx] = ranks
		}
		rank, ok := ranks[d]
		return rank, ok
	}

	for _, d := range item.group.Dialers {
		property := d.Property()
		if property == nil {
			continue
		}
		memberID := nodeIDOf(property)
		if _, seen := memberSamples[memberID]; !seen {
			memberOrder = append(memberOrder, memberID)
		}
		memberSamples[memberID] = mergeHealthSamples(memberSamples[memberID], dialerHealthSamples(d, rankOf))
	}

	// The delta is relative to the best member of the same health key, which is
	// only known once every member has been projected.
	bestByKey := make(map[string]float64, 6)
	for _, memberID := range memberOrder {
		for _, sample := range memberSamples[memberID] {
			if sample.sortingMs == nil {
				continue
			}
			key := healthObservationKey(sample.observation)
			if best, ok := bestByKey[key]; !ok || *sample.sortingMs < best {
				bestByKey[key] = *sample.sortingMs
			}
		}
	}

	observations := make([]nativeapi.GroupHealthObservation, 0, len(memberOrder)*2)
	for _, memberID := range memberOrder {
		for i := range memberSamples[memberID] {
			sample := &memberSamples[memberID][i]
			observation := nativeapi.GroupHealthObservation{
				HealthObservation: sample.observation,
				MemberID:          memberID,
				SortingLatencyMs:  sortingLatency(item.policy.Policy, *sample),
			}
			if sample.sortingMs != nil {
				// The engine's value, which already carries the recovery penalty
				// and the manual offset; the policy metric above does not.
				observation.SortingLatencyMs = sample.sortingMs
				if best, ok := bestByKey[healthObservationKey(sample.observation)]; ok {
					delta := *sample.sortingMs - best
					sample.deltaToBest = &delta
				}
				observation.Ranking = buildRanking(item.policy.Policy, *sample)
			}
			observations = append(observations, observation)
		}
	}
	return observations
}

// buildRanking explains the score a member received for one health key.
func buildRanking(policy consts.DialerSelectionPolicy, sample healthSample) *nativeapi.GroupRanking {
	if sample.sortingMs == nil {
		return nil
	}
	metric := string(policy)
	reason := "ranked by " + metric
	ranking := &nativeapi.GroupRanking{
		Metric:        &metric,
		GroupOffsetMs: sample.offsetMs,
		Score:         sample.sortingMs,
		Rank:          sample.rank,
		DeltaToBestMs: sample.deltaToBest,
		Reason:        &reason,
	}
	// The recovery penalty is what the alive set added on top of the policy
	// metric it read; sorting = metric + penalty + offset.
	if metricMs := sortingLatency(policy, sample); metricMs != nil {
		penalty := *sample.sortingMs - *metricMs
		if sample.offsetMs != nil {
			penalty -= *sample.offsetMs
		}
		ranking.RecoveryPenaltyMs = &penalty
	}
	return ranking
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
