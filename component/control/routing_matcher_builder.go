/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package control

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/component/routing"
	"net/netip"
	"strconv"
)

type DomainSet struct {
	Key       string
	RuleIndex int
	Domains   []string
}
type RoutingMatcherBuilder struct {
	*routing.DefaultMatcherBuilder
	outboundName2Id    map[string]uint8
	bpf                *bpfObjects
	rules              []bpfRouting
	SimulatedLpmTries  [][]netip.Prefix
	SimulatedDomainSet []DomainSet
	Final              string

	err error
}

func NewRoutingMatcherBuilder(outboundName2Id map[string]uint8, bpf *bpfObjects) *RoutingMatcherBuilder {
	return &RoutingMatcherBuilder{outboundName2Id: outboundName2Id, bpf: bpf}
}

func (b *RoutingMatcherBuilder) OutboundToId(outbound string) uint8 {
	var outboundId uint8
	if outbound == routing.FakeOutbound_AND {
		outboundId = uint8(consts.OutboundLogicalAnd)
	} else {
		var ok bool
		outboundId, ok = b.outboundName2Id[outbound]
		if !ok {
			b.err = fmt.Errorf("%v not in outboundName2Id", strconv.Quote(outbound))
		}
	}
	return outboundId
}

func (b *RoutingMatcherBuilder) AddDomain(key string, values []string, outbound string) {
	if b.err != nil {
		return
	}
	switch key {
	case consts.RoutingDomain_Regex,
		consts.RoutingDomain_Full,
		consts.RoutingDomain_Keyword,
		consts.RoutingDomain_Suffix:
	default:
		b.err = fmt.Errorf("AddDomain: unsupported key: %v", key)
		return
	}
	b.SimulatedDomainSet = append(b.SimulatedDomainSet, DomainSet{
		Key:       key,
		RuleIndex: len(b.rules),
		Domains:   values,
	})
	b.rules = append(b.rules, bpfRouting{
		Type:     uint8(consts.RoutingType_DomainSet),
		Outbound: b.OutboundToId(outbound),
	})
}

func (b *RoutingMatcherBuilder) AddIp(values []netip.Prefix, outbound string) {
	if b.err != nil {
		return
	}
	lpmTrieIndex := len(b.SimulatedLpmTries)
	b.SimulatedLpmTries = append(b.SimulatedLpmTries, values)
	b.rules = append(b.rules, bpfRouting{
		Type:     uint8(consts.RoutingType_IpSet),
		Value:    uint32(lpmTrieIndex),
		Outbound: b.OutboundToId(outbound),
	})
}

func (b *RoutingMatcherBuilder) AddFinal(outbound string) {
	if b.err != nil {
		return
	}
	b.Final = outbound
	b.rules = append(b.rules, bpfRouting{
		Type:     uint8(consts.RoutingType_Final),
		Outbound: b.OutboundToId(outbound),
	})
}

func (b *RoutingMatcherBuilder) Build() (err error) {
	if b.err != nil {
		return b.err
	}
	// Update lpm_array_map.
	for i, cidrs := range b.SimulatedLpmTries {
		var keys []bpfLpmKey
		var values []uint32
		for _, cidr := range cidrs {
			keys = append(keys, cidrToBpfLpmKey(cidr))
			values = append(values, 1)
		}
		m, err := b.bpf.NewLpmMap(keys, values)
		if err != nil {
			return fmt.Errorf("NewLpmMap: %w", err)
		}
		// ebpf.Map cannot be BatchUpdate
		if err = b.bpf.LpmArrayMap.Update(uint32(i), m, ebpf.UpdateAny); err != nil {
			m.Close()
			return fmt.Errorf("Update: %w", err)
		}
		m.Close()
	}
	// Update routings.
	routingsLen := uint32(len(b.rules))
	routingsKeys := common.ARangeU32(routingsLen)
	if _, err = b.bpf.RoutingMap.BatchUpdate(routingsKeys, b.rules, &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		return fmt.Errorf("BatchUpdate: %w", err)
	}
	if err = b.bpf.ParamMap.Update(consts.RoutingsLenKey, routingsLen, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("Update: %w", err)
	}
	return nil
}
