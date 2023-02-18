/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"github.com/Asphaltt/lpmtrie"
	"github.com/cilium/ebpf"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/component/routing"
	"github.com/v2rayA/dae/component/routing/domain_matcher"
	"github.com/v2rayA/dae/pkg/config_parser"
	"net/netip"
	"strconv"
)

type RoutingMatcherBuilder struct {
	*routing.DefaultMatcherBuilder
	outboundName2Id    map[string]uint8
	bpf                *bpfObjects
	rules              []bpfMatchSet
	simulatedLpmTries  [][]netip.Prefix
	simulatedDomainSet []routing.DomainSet
	Fallback           string

	err error
}

func NewRoutingMatcherBuilder(outboundName2Id map[string]uint8, bpf *bpfObjects) *RoutingMatcherBuilder {
	return &RoutingMatcherBuilder{outboundName2Id: outboundName2Id, bpf: bpf}
}

func (b *RoutingMatcherBuilder) OutboundToId(outbound string) uint8 {
	var outboundId uint8
	switch outbound {
	case routing.FakeOutbound_MUST_DIRECT:
		outboundId = uint8(consts.OutboundMustDirect)
	case routing.FakeOutbound_AND:
		outboundId = uint8(consts.OutboundLogicalAnd)
	case routing.FakeOutbound_OR:
		outboundId = uint8(consts.OutboundLogicalOr)
	default:
		var ok bool
		outboundId, ok = b.outboundName2Id[outbound]
		if !ok {
			b.err = fmt.Errorf("%v not defined in group", strconv.Quote(outbound))
		}
	}
	return outboundId
}

func (b *RoutingMatcherBuilder) AddDomain(f *config_parser.Function, key string, values []string, outbound string) {
	if b.err != nil {
		return
	}
	switch consts.RoutingDomainKey(key) {
	case consts.RoutingDomainKey_Regex,
		consts.RoutingDomainKey_Full,
		consts.RoutingDomainKey_Keyword,
		consts.RoutingDomainKey_Suffix:
	default:
		b.err = fmt.Errorf("AddDomain: unsupported key: %v", key)
		return
	}
	b.simulatedDomainSet = append(b.simulatedDomainSet, routing.DomainSet{
		Key:       consts.RoutingDomainKey(key),
		RuleIndex: len(b.rules),
		Domains:   values,
	})
	b.rules = append(b.rules, bpfMatchSet{
		Type:     uint8(consts.MatchType_DomainSet),
		Not:      f.Not,
		Outbound: b.OutboundToId(outbound),
	})
}

func (b *RoutingMatcherBuilder) AddSourceMac(f *config_parser.Function, macAddrs [][6]byte, outbound string) {
	if b.err != nil {
		return
	}
	var addr16 [16]byte
	values := make([]netip.Prefix, 0, len(macAddrs))
	for _, mac := range macAddrs {
		copy(addr16[10:], mac[:])
		prefix := netip.PrefixFrom(netip.AddrFrom16(addr16), 128)
		values = append(values, prefix)
	}
	lpmTrieIndex := len(b.simulatedLpmTries)
	b.simulatedLpmTries = append(b.simulatedLpmTries, values)
	set := bpfMatchSet{
		Value:    [16]byte{},
		Type:     uint8(consts.MatchType_Mac),
		Not:      f.Not,
		Outbound: b.OutboundToId(outbound),
	}
	binary.LittleEndian.PutUint32(set.Value[:], uint32(lpmTrieIndex))
	b.rules = append(b.rules, set)

}

func (b *RoutingMatcherBuilder) AddIp(f *config_parser.Function, values []netip.Prefix, outbound string) {
	if b.err != nil {
		return
	}
	lpmTrieIndex := len(b.simulatedLpmTries)
	b.simulatedLpmTries = append(b.simulatedLpmTries, values)
	set := bpfMatchSet{
		Value:    [16]byte{},
		Type:     uint8(consts.MatchType_IpSet),
		Not:      f.Not,
		Outbound: b.OutboundToId(outbound),
	}
	binary.LittleEndian.PutUint32(set.Value[:], uint32(lpmTrieIndex))
	b.rules = append(b.rules, set)
}

func (b *RoutingMatcherBuilder) AddPort(f *config_parser.Function, values [][2]uint16, _outbound string) {
	for i, value := range values {
		outbound := routing.FakeOutbound_OR
		if i == len(values)-1 {
			outbound = _outbound
		}
		b.rules = append(b.rules, bpfMatchSet{
			Type: uint8(consts.MatchType_Port),
			Value: _bpfPortRange{
				PortStart: value[0],
				PortEnd:   value[1],
			}.Encode(),
			Not:      f.Not,
			Outbound: b.OutboundToId(outbound),
		})
	}
}

func (b *RoutingMatcherBuilder) AddSourceIp(f *config_parser.Function, values []netip.Prefix, outbound string) {
	if b.err != nil {
		return
	}
	lpmTrieIndex := len(b.simulatedLpmTries)
	b.simulatedLpmTries = append(b.simulatedLpmTries, values)
	set := bpfMatchSet{
		Value:    [16]byte{},
		Type:     uint8(consts.MatchType_SourceIpSet),
		Not:      f.Not,
		Outbound: b.OutboundToId(outbound),
	}
	binary.LittleEndian.PutUint32(set.Value[:], uint32(lpmTrieIndex))
	b.rules = append(b.rules, set)
}

func (b *RoutingMatcherBuilder) AddSourcePort(f *config_parser.Function, values [][2]uint16, _outbound string) {
	for i, value := range values {
		outbound := routing.FakeOutbound_OR
		if i == len(values)-1 {
			outbound = _outbound
		}
		b.rules = append(b.rules, bpfMatchSet{
			Type: uint8(consts.MatchType_SourcePort),
			Value: _bpfPortRange{
				PortStart: value[0],
				PortEnd:   value[1],
			}.Encode(),
			Not:      f.Not,
			Outbound: b.OutboundToId(outbound),
		})
	}
}

func (b *RoutingMatcherBuilder) AddL4Proto(f *config_parser.Function, values consts.L4ProtoType, outbound string) {
	if b.err != nil {
		return
	}
	b.rules = append(b.rules, bpfMatchSet{
		Value:    [16]byte{byte(values)},
		Type:     uint8(consts.MatchType_L4Proto),
		Not:      f.Not,
		Outbound: b.OutboundToId(outbound),
	})
}

func (b *RoutingMatcherBuilder) AddIpVersion(f *config_parser.Function, values consts.IpVersionType, outbound string) {
	if b.err != nil {
		return
	}
	b.rules = append(b.rules, bpfMatchSet{
		Value:    [16]byte{byte(values)},
		Type:     uint8(consts.MatchType_IpVersion),
		Not:      f.Not,
		Outbound: b.OutboundToId(outbound),
	})
}

func (b *RoutingMatcherBuilder) AddProcessName(f *config_parser.Function, values [][consts.TaskCommLen]byte, _outbound string) {
	for i, value := range values {
		outbound := routing.FakeOutbound_OR
		if i == len(values)-1 {
			outbound = _outbound
		}
		matchSet := bpfMatchSet{
			Type:     uint8(consts.MatchType_ProcessName),
			Not:      f.Not,
			Outbound: b.OutboundToId(outbound),
		}
		copy(matchSet.Value[:], value[:])
		b.rules = append(b.rules, matchSet)
	}
}

func (b *RoutingMatcherBuilder) AddFallback(outbound string) {
	if b.err != nil {
		return
	}
	b.Fallback = outbound
	b.rules = append(b.rules, bpfMatchSet{
		Type:     uint8(consts.MatchType_Fallback),
		Outbound: b.OutboundToId(outbound),
	})
}

func (b *RoutingMatcherBuilder) BuildKernspace() (err error) {
	if b.err != nil {
		return b.err
	}
	// Update lpm_array_map.
	for i, cidrs := range b.simulatedLpmTries {
		var keys []_bpfLpmKey
		var values []uint32
		for _, cidr := range cidrs {
			keys = append(keys, cidrToBpfLpmKey(cidr))
			values = append(values, 1)
		}
		m, err := b.bpf.newLpmMap(keys, values)
		if err != nil {
			return fmt.Errorf("newLpmMap: %w", err)
		}
		// We cannot invoke BpfMapBatchUpdate when value is ebpf.Map.
		if err = b.bpf.LpmArrayMap.Update(uint32(i), m, ebpf.UpdateAny); err != nil {
			m.Close()
			return fmt.Errorf("Update: %w", err)
		}
		m.Close()
	}
	// Write routings.
	// Fallback rule MUST be the last.
	if b.rules[len(b.rules)-1].Type != uint8(consts.MatchType_Fallback) {
		b.err = fmt.Errorf("fallback rule MUST be the last")
		return b.err
	}
	routingsLen := uint32(len(b.rules))
	routingsKeys := common.ARangeU32(routingsLen)
	if _, err = BpfMapBatchUpdate(b.bpf.RoutingMap, routingsKeys, b.rules, &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		return fmt.Errorf("BpfMapBatchUpdate: %w", err)
	}
	return nil
}

func (b *RoutingMatcherBuilder) BuildUserspace() (matcher *RoutingMatcher, err error) {
	if b.err != nil {
		return nil, b.err
	}
	var m RoutingMatcher
	// Update lpms.
	m.lpms = make([]lpmtrie.LpmTrie, len(b.simulatedLpmTries))
	for i, cidrs := range b.simulatedLpmTries {
		lpm, err := lpmtrie.New(128)
		if err != nil {
			return nil, err
		}
		for _, cidr := range cidrs {
			lpm.Update(cidrToLpmTrieKey(cidr), 1)
		}
		m.lpms[i] = lpm
	}
	// Build domainMatcher
	m.domainMatcher = domain_matcher.NewAhocorasick(consts.MaxMatchSetLen)
	for _, domains := range b.simulatedDomainSet {
		m.domainMatcher.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err = m.domainMatcher.Build(); err != nil {
		return nil, err
	}

	// Write routings.
	// Fallback rule MUST be the last.
	if b.rules[len(b.rules)-1].Type != uint8(consts.MatchType_Fallback) {
		b.err = fmt.Errorf("fallback rule MUST be the last")
		return nil, b.err
	}
	m.matches = b.rules

	return &m, nil
}
