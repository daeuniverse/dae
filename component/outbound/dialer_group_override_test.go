/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/stretchr/testify/require"
)

func TestDialerGroupOverridePinsAutomaticPolicy(t *testing.T) {
	group, dialers := newSelectGroup(t, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency}, 3)
	markDialersDead(group.MustGetAliveDialerSet(TestNetworkType), dialers...)

	// With no alive member the automatic policy has nothing to pick.
	_, _, err := group.Select(TestNetworkType, true)
	require.Error(t, err)

	revision, err := group.SetOverride(SelectionNetworkTCP, 2)
	require.NoError(t, err)
	require.EqualValues(t, 1, revision)

	selected, _, err := group.Select(TestNetworkType, true)
	require.NoError(t, err)
	require.Same(t, dialers[2], selected)

	// The per-transport pin leaves UDP alone, so the automatic policy still
	// runs there and has no alive member.
	markDialersDead(group.MustGetAliveDialerSet(TestDnsUdp4NetworkType), dialers...)
	_, _, err = group.Select(TestDnsUdp4NetworkType, true)
	require.Error(t, err)

	if index, pinned := group.Override(SelectionNetworkTCP); !pinned || index != 2 {
		t.Fatalf("tcp override = %d, %v", index, pinned)
	}
	if _, pinned := group.Override(SelectionNetworkUDP); pinned {
		t.Fatal("udp must stay unpinned")
	}
}

func TestDialerGroupOverrideIgnoresExclusion(t *testing.T) {
	group, dialers := newSelectGroup(t, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Random}, 2)
	_, err := group.SetOverride(SelectionNetworkTCP, 1)
	require.NoError(t, err)

	selected, _, _, err := group.SelectWithExclusionResult(TestNetworkType, true, dialers[1])
	require.NoError(t, err)
	require.Same(t, dialers[1], selected)
}

func TestDialerGroupClearOverrideReturnsToPolicy(t *testing.T) {
	group, dialers := newSelectGroup(t, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinMovingAverageLatencies}, 2)
	markDialersDead(group.MustGetAliveDialerSet(TestNetworkType), dialers...)
	_, err := group.SetOverride(SelectionNetworkTCP, 1)
	require.NoError(t, err)

	selected, _, err := group.Select(TestNetworkType, true)
	require.NoError(t, err)
	require.Same(t, dialers[1], selected)

	revision, err := group.ClearOverride(SelectionNetworkTCP)
	require.NoError(t, err)
	require.EqualValues(t, 2, revision)

	if _, pinned := group.Override(SelectionNetworkTCP); pinned {
		t.Fatal("override must be gone")
	}
	_, _, err = group.Select(TestNetworkType, true)
	require.Error(t, err)
}

func TestDialerGroupOverrideRejectsOutOfRange(t *testing.T) {
	group, _ := newSelectGroup(t, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Random}, 2)

	_, err := group.SetOverride(SelectionNetworkTCP, 2)
	require.Error(t, err)
	_, err = group.SetOverride("quic", 0)
	require.Error(t, err)
	_, err = group.ClearOverride("quic")
	require.Error(t, err)
	require.EqualValues(t, 0, group.SelectionRevision())
}

// A selector and a fixed group already own their member, so a pin must never
// change which dialer they return.
func TestDialerGroupOverrideDoesNotApplyToFixedOrSelector(t *testing.T) {
	for _, policy := range []consts.DialerSelectionPolicy{
		consts.DialerSelectionPolicy_Fixed,
		consts.DialerSelectionPolicy_Select,
	} {
		group, dialers := newSelectGroup(t, DialerSelectionPolicy{Policy: policy, FixedIndex: 0}, 2)
		_, err := group.SetOverride(SelectionNetworkTCP, 1)
		require.NoError(t, err)

		selected, _, err := group.Select(TestNetworkType, true)
		require.NoError(t, err)
		require.Same(t, dialers[0], selected, "policy %v must keep its own member", policy)
	}
}

func TestDialerGroupOverrideResetsOnReload(t *testing.T) {
	group, _ := newSelectGroup(t, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Random}, 3)
	_, err := group.SetOverride(SelectionNetworkTCP, 2)
	require.NoError(t, err)

	reloaded, dialers := newSelectGroup(t, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Random}, 3)
	_, err = reloaded.SetOverride(SelectionNetworkTCP, 1)
	require.NoError(t, err)
	selected, _, err := reloaded.Select(TestNetworkType, true)
	require.NoError(t, err)
	require.Same(t, dialers[1], selected)
}

func TestSupportsOverride(t *testing.T) {
	require.True(t, consts.DialerSelectionPolicy_Random.SupportsOverride())
	require.True(t, consts.DialerSelectionPolicy_MinLastLatency.SupportsOverride())
	require.True(t, consts.DialerSelectionPolicy_MinAverage10Latencies.SupportsOverride())
	require.True(t, consts.DialerSelectionPolicy_MinMovingAverageLatencies.SupportsOverride())
	require.False(t, consts.DialerSelectionPolicy_Fixed.SupportsOverride())
	require.False(t, consts.DialerSelectionPolicy_Select.SupportsOverride())
}

// An established-flow snapshot keeps the parent's pin state but only the
// selected dialer, so admission must not read the pin as gone.
func TestPinsSelectionSurvivesEstablishedFlowSnapshot(t *testing.T) {
	group, dialers := newSelectGroup(t, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency}, 3)
	if _, err := group.SetOverride(SelectionNetworkUDP, 2); err != nil {
		t.Fatal(err)
	}
	view := group.SnapshotForEstablishedFlow(dialers[2])
	require.True(t, view.PinsSelection(SelectionNetworkUDP))
	require.False(t, view.PinsSelection(SelectionNetworkTCP))

	if _, err := group.ClearOverride(SelectionNetworkUDP); err != nil {
		t.Fatal(err)
	}
	view = group.SnapshotForEstablishedFlow(dialers[2])
	require.False(t, view.PinsSelection(SelectionNetworkUDP))
}
