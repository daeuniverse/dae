/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
)

const (
	groupIDPrefix = "g_"
	nodeIDPrefix  = "n_"
	idDigestBytes = 6
)

// nativeActiveGeneration is the coherent view API reads share: the published
// control plane plus the configuration that produced it.
type nativeActiveGeneration struct {
	generation *runtimeGeneration
	groups     []*outbound.DialerGroup
	conf       *config.Config
}

func (p *nativeAPIProvider) activeGeneration() (*nativeActiveGeneration, error) {
	active := p.supervisor.activeSnapshot()
	if active == nil || active.controlPlane == nil {
		return nil, fmt.Errorf("no active runtime generation")
	}
	return &nativeActiveGeneration{
		generation: active,
		groups:     active.controlPlane.OutboundGroups(),
		conf:       active.conf,
	}, nil
}

// userGroup is one user-configured group with its accepted configuration.
type userGroup struct {
	group  *outbound.DialerGroup
	conf   *config.Group
	policy outbound.DialerSelectionPolicy
}

func (a *nativeActiveGeneration) userGroups() []userGroup {
	byName := make(map[string]*config.Group)
	if a.conf != nil {
		for i := range a.conf.Group {
			byName[a.conf.Group[i].Name] = &a.conf.Group[i]
		}
	}
	groups := make([]userGroup, 0, len(a.groups))
	for _, group := range a.groups {
		if group == nil {
			continue
		}
		switch group.Name {
		case consts.OutboundDirect.String(), consts.OutboundBlock.String():
			continue
		}
		item := userGroup{
			group: group,
			conf:  byName[group.Name],
			policy: outbound.DialerSelectionPolicy{
				Policy: group.GetSelectionPolicy(),
			},
		}
		if item.conf != nil {
			if parsed, err := outbound.NewDialerSelectionPolicyFromGroupParam(item.conf); err == nil {
				item.policy = *parsed
			}
		}
		groups = append(groups, item)
	}
	return groups
}

func (a *nativeActiveGeneration) findGroup(groupID string) (userGroup, bool) {
	for _, item := range a.userGroups() {
		if groupIDOf(item.group.Name) == groupID {
			return item, true
		}
	}
	return userGroup{}, false
}

func (a *nativeActiveGeneration) configRevision() string {
	if a == nil || a.generation == nil {
		return ""
	}
	return a.generation.configRevision
}

func groupIDOf(name string) string {
	return groupIDPrefix + digest(name)[:idDigestBytes*2]
}

func nodeIDOf(property *dialer.Property) string {
	if property == nil {
		return nodeIDPrefix + digest("")[:idDigestBytes*2]
	}
	if property.Link != "" {
		return nodeIDPrefix + digest(property.Link)[:idDigestBytes*2]
	}
	return nodeIDPrefix + digest(property.Name + "\x00" + property.Address + "\x00" + property.Protocol)[:idDigestBytes*2]
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func policyKind(policy consts.DialerSelectionPolicy) string {
	switch policy {
	case consts.DialerSelectionPolicy_Select:
		return "selector"
	case consts.DialerSelectionPolicy_Fixed:
		return "fixed"
	case consts.DialerSelectionPolicy_Random:
		return "random"
	default:
		return "urltest"
	}
}

func policyNative(policy outbound.DialerSelectionPolicy) string {
	switch policy.Policy {
	case consts.DialerSelectionPolicy_Fixed:
		return fmt.Sprintf("fixed(%d)", policy.FixedIndex)
	case consts.DialerSelectionPolicy_Select:
		return fmt.Sprintf("select(%d)", policy.FixedIndex)
	default:
		return string(policy.Policy)
	}
}

func groupPolicyOf(policy outbound.DialerSelectionPolicy) nativeapi.GroupPolicy {
	return nativeapi.GroupPolicy{
		Kind:   policyKind(policy.Policy),
		Native: policyNative(policy),
	}
}

// groupMembers projects the group's dialers, keeping one member per node ID.
// Two subscriptions can carry the same link, which is the same node: the first
// occurrence owns the index so a member ID always names exactly one dialer.
func groupMembers(group *outbound.DialerGroup) ([]nativeapi.GroupMember, map[string]int) {
	members := make([]nativeapi.GroupMember, 0, len(group.Dialers))
	indexByID := make(map[string]int, len(group.Dialers))
	for i, d := range group.Dialers {
		property := d.Property()
		if property == nil {
			continue
		}
		id := nodeIDOf(property)
		if _, exists := indexByID[id]; exists {
			continue
		}
		indexByID[id] = i
		members = append(members, nativeapi.GroupMember{
			ID:   id,
			Name: property.Name,
			Kind: "node",
		})
	}
	return members, indexByID
}

func groupMemberCount(group *outbound.DialerGroup) int {
	members, _ := groupMembers(group)
	return len(members)
}

func memberIDAt(group *outbound.DialerGroup, index int) *string {
	if index < 0 || index >= len(group.Dialers) {
		return nil
	}
	id := nodeIDOf(group.Dialers[index].Property())
	return &id
}

// selectionPair reports the runtime selection of a group. A selector reports
// the runtime choice, a fixed group reports its configured member, and the
// automatic policies report nothing because they have no stable selection.
func selectionPair(item userGroup) nativeapi.GroupSelectionPair {
	switch item.policy.Policy {
	case consts.DialerSelectionPolicy_Select:
		return nativeapi.GroupSelectionPair{
			TCP: runtimeSelectionAt(item.group, outbound.SelectionNetworkTCP),
			UDP: runtimeSelectionAt(item.group, outbound.SelectionNetworkUDP),
		}
	case consts.DialerSelectionPolicy_Fixed:
		selection := selectionForMember(item.group, item.policy.FixedIndex, "policy")
		return nativeapi.GroupSelectionPair{TCP: selection, UDP: selection}
	default:
		if !item.policy.Policy.SupportsOverride() {
			return nativeapi.GroupSelectionPair{}
		}
		return nativeapi.GroupSelectionPair{
			TCP: overrideSelectionAt(item.group, outbound.SelectionNetworkTCP),
			UDP: overrideSelectionAt(item.group, outbound.SelectionNetworkUDP),
		}
	}
}

func overrideSelectionAt(group *outbound.DialerGroup, network outbound.SelectionNetwork) *nativeapi.GroupSelection {
	index, pinned := group.Override(network)
	if !pinned {
		return nil
	}
	return selectionForMember(group, index, "override")
}

func runtimeSelectionAt(group *outbound.DialerGroup, network outbound.SelectionNetwork) *nativeapi.GroupSelection {
	index, ok := group.Selection(network)
	if !ok {
		return nil
	}
	return selectionForMember(group, index, "runtime")
}

func selectionForMember(group *outbound.DialerGroup, index int, source string) *nativeapi.GroupSelection {
	memberID := memberIDAt(group, index)
	if memberID == nil {
		return nil
	}
	return &nativeapi.GroupSelection{
		MemberID:           *memberID,
		ResolvedLeafNodeID: nil,
		Source:             source,
	}
}

func groupConfigOf(item userGroup) nativeapi.GroupConfig {
	var config nativeapi.GroupConfig
	if item.policy.Policy == consts.DialerSelectionPolicy_Select ||
		item.policy.Policy == consts.DialerSelectionPolicy_Fixed {
		config.DefaultMemberID = memberIDAt(item.group, item.policy.FixedIndex)
	}
	extension := &nativeapi.GroupConfigExtension{}
	if item.conf != nil {
		if item.conf.CheckInterval > 0 {
			seconds := int(item.conf.CheckInterval / time.Second)
			config.CheckInterval = &seconds
		}
		if item.conf.CheckTolerance > 0 {
			tolerance := int(item.conf.CheckTolerance / time.Millisecond)
			config.Tolerance = &tolerance
		}
		extension.CheckAddresses = append([]string{}, item.conf.TcpCheckUrl...)
		extension.TCPCheckHTTPMethod = item.conf.TcpCheckHttpMethod
		extension.UDPCheckDNS = append([]string{}, item.conf.UdpCheckDns...)
	}
	if extension.CheckAddresses == nil {
		extension.CheckAddresses = []string{}
	}
	if extension.UDPCheckDNS == nil {
		extension.UDPCheckDNS = []string{}
	}
	config.XDae = extension
	return config
}

func groupCapabilitiesOf(item userGroup) nativeapi.GroupCapabilities {
	return nativeapi.GroupCapabilities{
		CanSelect:            item.policy.Policy == consts.DialerSelectionPolicy_Select,
		CanOverride:          item.policy.Policy.SupportsOverride(),
		SupportsNestedGroups: false,
		MutableConfig:        []string{},
		ProbeTransports:      []string{},
	}
}

func (p *nativeAPIProvider) ListGroups(ctx context.Context) ([]nativeapi.GroupSummary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	active, err := p.activeGeneration()
	if err != nil {
		return nil, err
	}
	revision := active.configRevision()
	summaries := make([]nativeapi.GroupSummary, 0, len(active.groups))
	for _, item := range active.userGroups() {
		selection := selectionPair(item)
		summary := nativeapi.GroupSummary{
			ID:             groupIDOf(item.group.Name),
			Name:           item.group.Name,
			Icon:           nil,
			ConfigRevision: revision,
			Policy:         groupPolicyOf(item.policy),
			MemberCount:    groupMemberCount(item.group),
			Selection: nativeapi.GroupSummarySelection{
				TCPMemberID: selectionMemberID(selection.TCP),
				UDPMemberID: selectionMemberID(selection.UDP),
			},
		}
		summaries = append(summaries, summary)
	}
	return summaries, nil
}

func selectionMemberID(selection *nativeapi.GroupSelection) *string {
	if selection == nil {
		return nil
	}
	return &selection.MemberID
}

func (p *nativeAPIProvider) GetGroup(ctx context.Context, groupID string) (*nativeapi.Group, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	active, err := p.activeGeneration()
	if err != nil {
		return nil, err
	}
	item, ok := active.findGroup(groupID)
	if !ok {
		return nil, nativeapi.NewAPIError(404, "resource_not_found", "group not found")
	}
	members, _ := groupMembers(item.group)
	group := &nativeapi.Group{
		ID:             groupIDOf(item.group.Name),
		Name:           item.group.Name,
		Icon:           nil,
		ConfigRevision: active.configRevision(),
		Policy:         groupPolicyOf(item.policy),
		Members:        members,
		Config:         groupConfigOf(item),
		Runtime: nativeapi.GroupRuntime{
			Selection: selectionPair(item),
			Health:    groupMemberHealth(item),
		},
		Capabilities: groupCapabilitiesOf(item),
	}
	return group, nil
}

func (p *nativeAPIProvider) GetGroupConfig(ctx context.Context, groupID string) (nativeapi.GroupConfigDocument, string, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.GroupConfigDocument{}, "", err
	}
	active, err := p.activeGeneration()
	if err != nil {
		return nativeapi.GroupConfigDocument{}, "", err
	}
	item, ok := active.findGroup(groupID)
	if !ok {
		return nativeapi.GroupConfigDocument{}, "", nativeapi.NewAPIError(404, "resource_not_found", "group not found")
	}
	return nativeapi.GroupConfigDocument{
		Policy: groupPolicyOf(item.policy),
		Config: groupConfigOf(item),
	}, active.configRevision(), nil
}

func (p *nativeAPIProvider) SetGroupSelection(ctx context.Context, groupID, memberID, network string) (nativeapi.GroupSelectionResult, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.GroupSelectionResult{}, err
	}
	active, err := p.activeGeneration()
	if err != nil {
		return nativeapi.GroupSelectionResult{}, err
	}
	item, ok := active.findGroup(groupID)
	if !ok {
		return nativeapi.GroupSelectionResult{}, nativeapi.NewAPIError(404, "resource_not_found", "group not found")
	}
	canSelect := item.policy.Policy == consts.DialerSelectionPolicy_Select
	canOverride := item.policy.Policy.SupportsOverride()
	if !canSelect && !canOverride {
		return nativeapi.GroupSelectionResult{}, nativeapi.NewAPIError(422, "unsupported_value",
			"the group policy does not accept a runtime selection")
	}
	_, indexByID := groupMembers(item.group)
	index, ok := indexByID[memberID]
	if !ok {
		return nativeapi.GroupSelectionResult{}, nativeapi.NewAPIError(422, "unsupported_value",
			"member_id is not a direct member of the group")
	}
	apply := func(slot outbound.SelectionNetwork) (uint64, error) {
		if canSelect {
			return item.group.SetSelection(slot, index)
		}
		return item.group.SetOverride(slot, index)
	}
	var revision uint64
	switch network {
	case "both":
		if revision, err = apply(outbound.SelectionNetworkTCP); err != nil {
			return nativeapi.GroupSelectionResult{}, selectionError(err)
		}
		if revision, err = apply(outbound.SelectionNetworkUDP); err != nil {
			return nativeapi.GroupSelectionResult{}, selectionError(err)
		}
	case "tcp":
		if revision, err = apply(outbound.SelectionNetworkTCP); err != nil {
			return nativeapi.GroupSelectionResult{}, selectionError(err)
		}
	case "udp":
		if revision, err = apply(outbound.SelectionNetworkUDP); err != nil {
			return nativeapi.GroupSelectionResult{}, selectionError(err)
		}
	default:
		return nativeapi.GroupSelectionResult{}, nativeapi.NewAPIError(400, "invalid_request",
			"network must be tcp, udp or both")
	}
	source := "runtime"
	if canOverride {
		source = "override"
	}
	return nativeapi.GroupSelectionResult{
		GroupID:                groupIDOf(item.group.Name),
		MemberID:               memberID,
		ResolvedLeafNodeID:     nil,
		Network:                network,
		Source:                 source,
		SelectionRevision:      strconv.FormatUint(revision, 10),
		ConnectionsInterrupted: false,
	}, nil
}

func selectionError(err error) error {
	if err == nil {
		return nil
	}
	return nativeapi.NewAPIError(422, "unsupported_value", err.Error())
}

func (p *nativeAPIProvider) ClearGroupSelection(ctx context.Context, groupID, network string) (nativeapi.GroupOverrideCleared, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.GroupOverrideCleared{}, err
	}
	active, err := p.activeGeneration()
	if err != nil {
		return nativeapi.GroupOverrideCleared{}, err
	}
	item, ok := active.findGroup(groupID)
	if !ok {
		return nativeapi.GroupOverrideCleared{}, nativeapi.NewAPIError(404, "resource_not_found", "group not found")
	}
	if item.policy.Policy == consts.DialerSelectionPolicy_Select {
		return nativeapi.GroupOverrideCleared{}, nativeapi.NewAPIError(409, "state_conflict",
			"a selector keeps its runtime choice; clear is not applicable")
	}
	if !item.policy.Policy.SupportsOverride() {
		return nativeapi.GroupOverrideCleared{}, nativeapi.NewAPIError(422, "unsupported_value",
			"the group policy never pins a member")
	}
	var revision uint64
	clearSlot := func(slot outbound.SelectionNetwork) error {
		var err error
		revision, err = item.group.ClearOverride(slot)
		return err
	}
	switch network {
	case "both":
		if err := clearSlot(outbound.SelectionNetworkTCP); err != nil {
			return nativeapi.GroupOverrideCleared{}, selectionError(err)
		}
		if err := clearSlot(outbound.SelectionNetworkUDP); err != nil {
			return nativeapi.GroupOverrideCleared{}, selectionError(err)
		}
	case "tcp":
		if err := clearSlot(outbound.SelectionNetworkTCP); err != nil {
			return nativeapi.GroupOverrideCleared{}, selectionError(err)
		}
	case "udp":
		if err := clearSlot(outbound.SelectionNetworkUDP); err != nil {
			return nativeapi.GroupOverrideCleared{}, selectionError(err)
		}
	default:
		return nativeapi.GroupOverrideCleared{}, nativeapi.NewAPIError(400, "invalid_request",
			"network must be tcp, udp or both")
	}
	// Automatic policies have no stable member to report once the pin is gone,
	// matching how runtime.selection already reports them.
	return nativeapi.GroupOverrideCleared{
		GroupID:                groupIDOf(item.group.Name),
		Network:                network,
		SelectionRevision:      strconv.FormatUint(revision, 10),
		ConnectionsInterrupted: false,
		Selection:              selectionPair(item),
	}, nil
}

func (p *nativeAPIProvider) TrafficHistory(ctx context.Context, windowSeconds, maxPoints int) (nativeapi.TrafficHistory, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.TrafficHistory{}, err
	}
	active := p.supervisor.activeSnapshot()
	if active == nil || active.controlPlane == nil {
		return nativeapi.TrafficHistory{}, fmt.Errorf("no active runtime generation")
	}
	stats := active.controlPlane.SnapshotRuntimeStats(windowSeconds, maxPoints)
	history := nativeapi.TrafficHistory{
		ObservedAt:          stats.UpdatedAt.UTC().Format(time.RFC3339),
		WindowSeconds:       windowSeconds,
		SampledEverySeconds: sampleIntervalSeconds(stats.Samples),
		Samples:             make([]nativeapi.TrafficHistorySample, 0, len(stats.Samples)),
	}
	for _, sample := range stats.Samples {
		upload := strconv.FormatUint(sample.UploadRate, 10)
		download := strconv.FormatUint(sample.DownloadRate, 10)
		history.Samples = append(history.Samples, nativeapi.TrafficHistorySample{
			SampledAt:              sample.Timestamp.UTC().Format(time.RFC3339),
			UploadBytesPerSecond:   &upload,
			DownloadBytesPerSecond: &download,
			Connections:            nil,
		})
	}
	return history, nil
}

// sampleIntervalSeconds reports the nominal spacing of the returned samples.
// Thinning widens it beyond the recorder interval, so it is measured from the
// samples rather than assumed.
func sampleIntervalSeconds(samples []control.RuntimeTrafficSample) float64 {
	if len(samples) < 2 {
		return control.RuntimeSampleInterval.Seconds()
	}
	var total time.Duration
	for i := 1; i < len(samples); i++ {
		total += samples[i].Timestamp.Sub(samples[i-1].Timestamp)
	}
	interval := total / time.Duration(len(samples)-1)
	if interval <= 0 {
		return control.RuntimeSampleInterval.Seconds()
	}
	return interval.Seconds()
}
