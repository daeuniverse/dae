/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type noopDialer struct{}

func (noopDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, errors.New("not implemented")
}

func newNamedDialer(option *dialer.GlobalOption, property *dialer.Property) *dialer.Dialer {
	return dialer.NewDialerContext(context.Background(), noopDialer{}, option,
		dialer.InstanceOption{DisableCheck: true}, property)
}

func newMappedGroup(t *testing.T, name string, policy outbound.DialerSelectionPolicy, properties ...*dialer.Property) userGroup {
	t.Helper()
	option := &dialer.GlobalOption{Log: logrus.New(), CheckInterval: 15 * time.Second}
	dialers := make([]*dialer.Dialer, 0, len(properties))
	annotations := make([]*dialer.Annotation, 0, len(properties))
	for _, property := range properties {
		dialers = append(dialers, newNamedDialer(option, property))
		annotations = append(annotations, &dialer.Annotation{})
	}
	group := outbound.NewDialerGroup(option, name, dialers, annotations, policy, func(bool, *dialer.NetworkType, bool) {})
	t.Cleanup(func() { _ = group.Close() })
	return userGroup{
		group: group,
		conf: &config.Group{
			Name:               name,
			Policy:             policyNative(policy),
			TcpCheckUrl:        []string{"https://check.example/204"},
			TcpCheckHttpMethod: "HEAD",
			UdpCheckDns:        []string{"dns.example"},
			CheckInterval:      10 * time.Second,
			CheckTolerance:     50 * time.Millisecond,
		},
		policy: policy,
	}
}

func testNodeProperties() []*dialer.Property {
	return []*dialer.Property{
		{Property: D.Property{Name: "hk-01", Address: "hk.example:443", Protocol: "ss", Link: "ss://hk"}},
		{Property: D.Property{Name: "jp-01", Address: "jp.example:443", Protocol: "ss", Link: "ss://jp"}},
	}
}

func TestGroupAndNodeIDsAreStable(t *testing.T) {
	require.Equal(t, groupIDOf("proxy"), groupIDOf("proxy"))
	require.NotEqual(t, groupIDOf("proxy"), groupIDOf("proxy2"))
	require.Len(t, groupIDOf("proxy"), len(groupIDPrefix)+12)

	properties := testNodeProperties()
	require.Equal(t, nodeIDOf(properties[0]), nodeIDOf(properties[0]))
	require.NotEqual(t, nodeIDOf(properties[0]), nodeIDOf(properties[1]))
	require.Len(t, nodeIDOf(properties[0]), len(nodeIDPrefix)+12)

	// A node keeps its ID as long as its link is unchanged, even if the
	// display name changes.
	renamed := &dialer.Property{Property: D.Property{
		Name:     "hk-renamed",
		Address:  properties[0].Address,
		Protocol: properties[0].Protocol,
		Link:     properties[0].Link,
	}}
	require.Equal(t, nodeIDOf(properties[0]), nodeIDOf(renamed))
}

func TestPolicyMapping(t *testing.T) {
	cases := []struct {
		policy outbound.DialerSelectionPolicy
		kind   string
		native string
	}{
		{outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Select, FixedIndex: 1}, "selector", "select(1)"},
		{outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 2}, "fixed", "fixed(2)"},
		{outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Random}, "random", "random"},
		{outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency}, "urltest", "min"},
		{outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinAverage10Latencies}, "urltest", "min_avg10"},
		{outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinMovingAverageLatencies}, "urltest", "min_moving_avg"},
	}
	for _, testCase := range cases {
		policy := groupPolicyOf(testCase.policy)
		require.Equal(t, testCase.kind, policy.Kind)
		require.Equal(t, testCase.native, policy.Native)
	}
}

func TestSelectGroupMapping(t *testing.T) {
	properties := testNodeProperties()
	item := newMappedGroup(t, "proxy", outbound.DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Select,
		FixedIndex: 1,
	}, properties...)

	selection := selectionPair(item)
	require.NotNil(t, selection.TCP)
	require.NotNil(t, selection.UDP)
	require.Equal(t, nodeIDOf(properties[1]), selection.TCP.MemberID)
	require.Equal(t, "runtime", selection.TCP.Source)

	groupConfig := groupConfigOf(item)
	require.NotNil(t, groupConfig.DefaultMemberID)
	require.Equal(t, nodeIDOf(properties[1]), *groupConfig.DefaultMemberID)
	require.Nil(t, groupConfig.CheckURL)
	require.Nil(t, groupConfig.FinalOutbound)
	require.Nil(t, groupConfig.IdleTimeout)
	require.Nil(t, groupConfig.InterruptConnections)
	require.Equal(t, 10, *groupConfig.CheckInterval)
	require.Equal(t, 50, *groupConfig.Tolerance)
	require.NotNil(t, groupConfig.XDae)
	require.Equal(t, []string{"https://check.example/204"}, groupConfig.XDae.CheckAddresses)
	require.Equal(t, "HEAD", groupConfig.XDae.TCPCheckHTTPMethod)
	require.Equal(t, []string{"dns.example"}, groupConfig.XDae.UDPCheckDNS)

	capabilities := groupCapabilitiesOf(item)
	require.True(t, capabilities.CanSelect)
	require.False(t, capabilities.CanOverride)
	require.False(t, capabilities.SupportsNestedGroups)
	require.Empty(t, capabilities.MutableConfig)
	require.Empty(t, capabilities.ProbeTransports)
}

func TestSelectGroupRuntimeSwitchChangesReportedSelection(t *testing.T) {
	properties := testNodeProperties()
	item := newMappedGroup(t, "proxy", outbound.DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Select,
	}, properties...)

	_, err := item.group.SetSelection(outbound.SelectionNetworkTCP, 1)
	require.NoError(t, err)
	selection := selectionPair(item)
	require.Equal(t, nodeIDOf(properties[1]), selection.TCP.MemberID)
	require.Equal(t, nodeIDOf(properties[0]), selection.UDP.MemberID)
	require.EqualValues(t, 1, item.group.SelectionRevision())
}

func TestFixedGroupReportsConfiguredMember(t *testing.T) {
	properties := testNodeProperties()
	item := newMappedGroup(t, "fixed-group", outbound.DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: 1,
	}, properties...)

	selection := selectionPair(item)
	require.NotNil(t, selection.TCP)
	require.Equal(t, nodeIDOf(properties[1]), selection.TCP.MemberID)
	require.Equal(t, "policy", selection.TCP.Source)
}

func TestAutomaticGroupHasNoSelection(t *testing.T) {
	properties := testNodeProperties()
	item := newMappedGroup(t, "auto", outbound.DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_MinLastLatency,
	}, properties...)

	selection := selectionPair(item)
	require.Nil(t, selection.TCP)
	require.Nil(t, selection.UDP)
}

func TestSampleIntervalFollowsThinning(t *testing.T) {
	require.InDelta(t, 0.25, sampleIntervalSeconds(nil), 1e-9)

	base := time.Unix(0, 0)
	samples := make([]control.RuntimeTrafficSample, 0, 4)
	for i := range 4 {
		samples = append(samples, control.RuntimeTrafficSample{Timestamp: base.Add(time.Duration(i) * 20 * time.Second)})
	}
	require.InDelta(t, 20, sampleIntervalSeconds(samples), 1e-9)
}
