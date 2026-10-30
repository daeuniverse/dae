/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/stretchr/testify/require"
)

func newSelectGroup(t *testing.T, policy DialerSelectionPolicy, dialers int) (*DialerGroup, []*dialer.Dialer) {
	t.Helper()
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	fixtures := make([]*dialer.Dialer, 0, dialers)
	for range dialers {
		fixtures = append(fixtures, newDirectDialer(option))
	}
	group := NewDialerGroup(option, "select-group", fixtures, newEmptyAnnotations(len(fixtures)), policy, func(bool, *dialer.NetworkType, bool) {})
	t.Cleanup(func() { _ = group.Close() })
	return group, fixtures
}

func TestDialerGroupSelectDefaultMember(t *testing.T) {
	group, dialers := newSelectGroup(t, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Select}, 3)

	selected, _, err := group.Select(TestNetworkType, false)
	require.NoError(t, err)
	require.Same(t, dialers[0], selected)

	selected, _, err = group.Select(TestDataUdp4NetworkType, false)
	require.NoError(t, err)
	require.Same(t, dialers[0], selected)

	require.EqualValues(t, 0, group.SelectionRevision())
}

func TestDialerGroupSelectConfiguredInitialMember(t *testing.T) {
	group, dialers := newSelectGroup(t, DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Select,
		FixedIndex: 1,
	}, 3)

	selected, _, err := group.Select(TestNetworkType, false)
	require.NoError(t, err)
	require.Same(t, dialers[1], selected)
}

func TestDialerGroupSelectSwitchesPerTransport(t *testing.T) {
	group, dialers := newSelectGroup(t, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Select}, 3)

	revision, err := group.SetSelection(SelectionNetworkTCP, 2)
	require.NoError(t, err)
	require.EqualValues(t, 1, revision)

	selected, _, err := group.Select(TestNetworkType, false)
	require.NoError(t, err)
	require.Same(t, dialers[2], selected)

	// UDP keeps its own choice, and DNS UDP follows the UDP choice.
	selected, _, err = group.Select(TestDataUdp4NetworkType, false)
	require.NoError(t, err)
	require.Same(t, dialers[0], selected)

	revision, err = group.SetSelection(SelectionNetworkUDP, 1)
	require.NoError(t, err)
	require.EqualValues(t, 2, revision)

	selected, _, err = group.Select(TestDnsUdp4NetworkType, false)
	require.NoError(t, err)
	require.Same(t, dialers[1], selected)

	if index, ok := group.Selection(SelectionNetworkTCP); !ok || index != 2 {
		t.Fatalf("tcp selection = %d, %v", index, ok)
	}
	if index, ok := group.Selection(SelectionNetworkUDP); !ok || index != 1 {
		t.Fatalf("udp selection = %d, %v", index, ok)
	}
	require.EqualValues(t, 2, group.SelectionRevision())
}

func TestDialerGroupSelectRejectsOutOfRangeSelection(t *testing.T) {
	group, _ := newSelectGroup(t, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Select}, 2)

	_, err := group.SetSelection(SelectionNetworkTCP, 2)
	require.Error(t, err)
	_, err = group.SetSelection(SelectionNetworkTCP, -1)
	require.Error(t, err)
	_, err = group.SetSelection("quic", 0)
	require.Error(t, err)
	require.EqualValues(t, 0, group.SelectionRevision())
}

// A reload builds a fresh generation, so the runtime choice must fall back to
// the configured index instead of surviving in memory.
func TestDialerGroupSelectResetsOnReload(t *testing.T) {
	group, _ := newSelectGroup(t, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Select}, 3)
	_, err := group.SetSelection(SelectionNetworkTCP, 2)
	require.NoError(t, err)

	reloaded, dialers := newSelectGroup(t, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Select}, 3)
	selected, _, err := reloaded.Select(TestNetworkType, false)
	require.NoError(t, err)
	require.Same(t, dialers[0], selected)
}

func TestDialerGroupSelectIgnoresExclusionAndHealth(t *testing.T) {
	group, dialers := newSelectGroup(t, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Select}, 2)

	selected, _, _, err := group.SelectWithExclusionResult(TestNetworkType, true, dialers[0])
	require.NoError(t, err)
	require.Same(t, dialers[0], selected)
}

// An empty group stays a tolerated state: the filter may match nodes again
// after the next subscription update, so selection reports the missing members
// instead of failing construction.
func TestDialerGroupSelectEmptyGroup(t *testing.T) {
	group, _ := newSelectGroup(t, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Select}, 0)

	if index, ok := group.Selection(SelectionNetworkTCP); !ok || index != 0 {
		t.Fatalf("empty group selection = %d, %v", index, ok)
	}
	_, _, err := group.Select(TestNetworkType, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no dialer")
}

func TestDialerGroupSelectPoliciesKeepKernelAdmissionOpen(t *testing.T) {
	require.True(t, groupPublishesOptimisticAlive(consts.DialerSelectionPolicy_Select))
	require.False(t, policyNeedsAliveState(consts.DialerSelectionPolicy_Select))
	require.True(t, consts.DialerSelectionPolicy_Select.IgnoresDialerHealth())
}
