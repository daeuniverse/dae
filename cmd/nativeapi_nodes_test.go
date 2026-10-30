/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func healthTestDialer(t *testing.T) *dialer.Dialer {
	t.Helper()
	option := &dialer.GlobalOption{Log: logrus.New(), CheckInterval: 15 * time.Second}
	d := newNamedDialer(option, &dialer.Property{Property: D.Property{Name: "hk-01"}})
	var snapshot dialer.DialerHealthSnapshot
	snapshot.Collections[dialer.IdxTcp4] = dialer.DialerCollectionHealthSnapshot{
		Alive:         true,
		MovingAverage: 47 * time.Millisecond,
		Latencies: dialer.LatenciesNSnapshot{
			Latencies:     []time.Duration{40 * time.Millisecond, 50 * time.Millisecond},
			SumNLatencies: 90 * time.Millisecond,
		},
		LastProbe: dialer.DialerProbeObservationSnapshot{
			CheckedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			Alive:      true,
			Latency:    45 * time.Millisecond,
			HasLatency: true,
			Message:    "45ms",
		},
	}
	snapshot.Collections[dialer.IdxDnsUdp4] = dialer.DialerCollectionHealthSnapshot{
		Alive: false,
		LastProbe: dialer.DialerProbeObservationSnapshot{
			CheckedAt: time.Date(2026, 1, 1, 0, 0, 5, 0, time.UTC),
			Alive:     false,
			Message:   "udp probe timeout: context deadline exceeded",
		},
	}
	d.RestoreHealthSnapshot(snapshot)
	return d
}

func TestDialerHealthSamples(t *testing.T) {
	d := healthTestDialer(t)
	samples := dialerHealthSamples(d)
	require.Len(t, samples, 2)

	byPurpose := map[string]healthSample{}
	for _, sample := range samples {
		byPurpose[sample.observation.Purpose] = sample
	}

	tcp := byPurpose["shared"]
	require.Equal(t, "tcp", tcp.observation.Transport)
	require.Equal(t, "shared", tcp.observation.Purpose)
	require.Equal(t, "ipv4", tcp.observation.IpVersion)
	require.Equal(t, "healthy", tcp.observation.State)
	require.Equal(t, "http_headers", tcp.observation.Measurement)
	require.Equal(t, "probe", tcp.observation.SampleSource)
	require.Equal(t, "unknown", tcp.observation.Warmth)
	require.Nil(t, tcp.observation.Error)
	require.NotNil(t, tcp.observation.LatencyMs)
	require.InDelta(t, 45, *tcp.observation.LatencyMs, 1e-9)
	require.NotNil(t, tcp.observation.MovingAvgMs)
	require.InDelta(t, 47, *tcp.observation.MovingAvgMs, 1e-9)
	require.NotNil(t, tcp.observation.Avg10Ms)
	require.InDelta(t, 45, *tcp.observation.Avg10Ms, 1e-9)
	require.Equal(t, "2026-01-01T00:00:00Z", tcp.observation.ObservedAt)

	udp := byPurpose["dns"]
	require.Equal(t, "udp", udp.observation.Transport)
	require.Equal(t, "dns", udp.observation.Purpose)
	require.Equal(t, "dns_round_trip", udp.observation.Measurement)
	require.Equal(t, "unavailable", udp.observation.State)
	require.Nil(t, udp.observation.LatencyMs)
	// Engine error detail stays out of the response.
	require.NotNil(t, udp.observation.Error)
	require.Equal(t, "probe_failed", *udp.observation.Error)
}

func TestDialerHealthSamplesSkipUnprobedCollections(t *testing.T) {
	option := &dialer.GlobalOption{Log: logrus.New(), CheckInterval: 15 * time.Second}
	d := newNamedDialer(option, &dialer.Property{Property: D.Property{Name: "fresh"}})
	require.Empty(t, dialerHealthSamples(d))
	require.Empty(t, dialerHealthObservations(d))
}

func TestGroupMemberHealthSortingLatency(t *testing.T) {
	properties := testNodeProperties()
	item := newMappedGroup(t, "proxy", outbound.DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_MinAverage10Latencies,
	}, properties...)
	// Attach health to one member so the projection has data.
	observations := groupMemberHealth(item)
	require.Empty(t, observations, "no probed member yet")

	healthy := healthTestDialer(t)
	item.group.Dialers = append(item.group.Dialers, healthy)
	observations = groupMemberHealth(item)
	require.Len(t, observations, 2)
	for _, observation := range observations {
		require.Equal(t, nodeIDOf(healthy.Property()), observation.MemberID)
		require.Nil(t, observation.Ranking)
		if observation.Transport == "tcp" {
			// min_avg10 sorts by the 10-sample average.
			require.NotNil(t, observation.SortingLatencyMs)
			require.InDelta(t, 45, *observation.SortingLatencyMs, 1e-9)
		} else {
			require.Nil(t, observation.SortingLatencyMs)
		}
	}
}

func TestGroupCapabilitiesForAutomaticPolicies(t *testing.T) {
	properties := testNodeProperties()
	cases := []struct {
		policy      consts.DialerSelectionPolicy
		kind        string
		canSelect   bool
		canOverride bool
	}{
		{consts.DialerSelectionPolicy_Select, "selector", true, false},
		{consts.DialerSelectionPolicy_Fixed, "fixed", false, false},
		{consts.DialerSelectionPolicy_Random, "random", false, true},
		{consts.DialerSelectionPolicy_MinLastLatency, "urltest", false, true},
	}
	for _, testCase := range cases {
		item := newMappedGroup(t, "g", outbound.DialerSelectionPolicy{Policy: testCase.policy}, properties...)
		capabilities := groupCapabilitiesOf(item)
		require.Equal(t, testCase.canSelect, capabilities.CanSelect, "can_select for %v", testCase.policy)
		require.Equal(t, testCase.canOverride, capabilities.CanOverride, "can_override for %v", testCase.policy)
		require.Equal(t, testCase.kind, groupPolicyOf(item.policy).Kind)
	}
}

func TestOverrideSelectionIsReported(t *testing.T) {
	properties := testNodeProperties()
	item := newMappedGroup(t, "auto", outbound.DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_MinLastLatency,
	}, properties...)

	require.Nil(t, selectionPair(item).TCP, "an automatic group has no stable selection")

	_, err := item.group.SetOverride(outbound.SelectionNetworkTCP, 1)
	require.NoError(t, err)
	selection := selectionPair(item)
	require.NotNil(t, selection.TCP)
	require.Equal(t, "override", selection.TCP.Source)
	require.Equal(t, nodeIDOf(properties[1]), selection.TCP.MemberID)
	require.Nil(t, selection.UDP)

	_, err = item.group.ClearOverride(outbound.SelectionNetworkTCP)
	require.NoError(t, err)
	require.Nil(t, selectionPair(item).TCP)
}

func TestNodeCursorRoundTrip(t *testing.T) {
	cursor := nodeCursor{generation: "gen-1", offset: 42}
	encoded := encodeNodeCursor(cursor)
	decoded, ok := decodeNodeCursor(encoded)
	require.True(t, ok)
	require.Equal(t, cursor, decoded)

	for _, invalid := range []string{"not-base64!!", "bm9jb2xvbg", "Z2VuLTE6LTE", "OjE"} {
		if _, ok := decodeNodeCursor(invalid); ok {
			t.Fatalf("cursor %q must be rejected", invalid)
		}
	}
}

func TestMergeSortedStrings(t *testing.T) {
	require.Equal(t, []string{}, mergeSortedStrings(nil, nil))
	require.Equal(t, []string{"g_1", "g_2"}, mergeSortedStrings([]string{"g_2"}, []string{"g_1", "g_2"}))
}

func TestMergeHealthObservationsKeepsNewestPerKey(t *testing.T) {
	older := nativeapiHealth("tcp", "shared", "ipv4", "2026-01-01T00:00:00Z", "unavailable")
	newer := nativeapiHealth("tcp", "shared", "ipv4", "2026-01-01T00:05:00Z", "healthy")
	other := nativeapiHealth("udp", "dns", "ipv4", "2026-01-01T00:00:00Z", "healthy")

	merged := mergeHealthObservations([]nativeapi.HealthObservation{older}, []nativeapi.HealthObservation{newer, other})
	require.Len(t, merged, 2)
	require.Equal(t, "healthy", merged[0].State)
	require.Equal(t, "2026-01-01T00:05:00Z", merged[0].ObservedAt)
	require.Equal(t, "dns", merged[1].Purpose)

	// A candidate without a parsable timestamp never replaces a known one.
	broken := nativeapiHealth("tcp", "shared", "ipv4", "", "unavailable")
	merged = mergeHealthObservations([]nativeapi.HealthObservation{newer}, []nativeapi.HealthObservation{broken})
	require.Equal(t, "healthy", merged[0].State)
}

func nativeapiHealth(transport, purpose, ipVersion, observedAt, state string) nativeapi.HealthObservation {
	return nativeapi.HealthObservation{
		Transport:    transport,
		Purpose:      purpose,
		IpVersion:    ipVersion,
		Warmth:       "unknown",
		Measurement:  "http_headers",
		SampleSource: "probe",
		State:        state,
		ObservedAt:   observedAt,
	}
}

func TestGroupMembersCollapseDuplicateLinks(t *testing.T) {
	sharedLink := "ss://same-node"
	properties := []*dialer.Property{
		{Property: D.Property{Name: "a", Link: sharedLink}},
		{Property: D.Property{Name: "a-copy", Link: sharedLink}},
		{Property: D.Property{Name: "b", Link: "ss://other-node"}},
	}
	item := newMappedGroup(t, "proxy", outbound.DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Select,
	}, properties...)

	members, indexByID := groupMembers(item.group)
	require.Len(t, members, 2, "the same share link is the same node")
	require.Equal(t, 2, groupMemberCount(item.group))
	require.Contains(t, indexByID, members[0].ID)
	require.Contains(t, indexByID, members[1].ID)
}

func TestGroupMemberHealthCollapsesDuplicateLinks(t *testing.T) {
	sharedLink := "ss://same-node"
	option := &dialer.GlobalOption{Log: logrus.New(), CheckInterval: 15 * time.Second}
	quiet := newNamedDialer(option, &dialer.Property{Property: D.Property{Name: "a", Link: sharedLink}})
	probed := healthTestDialer(t)
	probed.Property().Link = sharedLink

	group := outbound.NewDialerGroup(option, "proxy", []*dialer.Dialer{quiet, probed},
		[]*dialer.Annotation{{}, {}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(bool, *dialer.NetworkType, bool) {})
	t.Cleanup(func() { _ = group.Close() })

	item := userGroup{
		group:  group,
		policy: outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
	}
	observations := groupMemberHealth(item)
	// Two domains (DNS-UDP + TCP) for one member, not four.
	require.Len(t, observations, 2)
	for _, observation := range observations {
		require.Equal(t, nodeIDOf(probed.Property()), observation.MemberID)
	}
}
