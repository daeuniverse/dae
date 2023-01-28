/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 <mzz@tuta.io>
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
		Type:     uint32(consts.RoutingType_DomainSet),
		Outbound: b.OutboundToId(outbound),
	})
}

func (b *RoutingMatcherBuilder) AddSourceMac(macAddrs [][6]byte, outbound string) {
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
	lpmTrieIndex := len(b.SimulatedLpmTries)
	b.SimulatedLpmTries = append(b.SimulatedLpmTries, values)
	b.rules = append(b.rules, bpfRouting{
		Type:     uint32(consts.RoutingType_Mac),
		Value:    uint32(lpmTrieIndex),
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
		Type:     uint32(consts.RoutingType_IpSet),
		Value:    uint32(lpmTrieIndex),
		Outbound: b.OutboundToId(outbound),
	})
}

func (b *RoutingMatcherBuilder) AddSourceIp(values []netip.Prefix, outbound string) {
	if b.err != nil {
		return
	}
	lpmTrieIndex := len(b.SimulatedLpmTries)
	b.SimulatedLpmTries = append(b.SimulatedLpmTries, values)
	b.rules = append(b.rules, bpfRouting{
		Type:     uint32(consts.RoutingType_SourceIpSet),
		Value:    uint32(lpmTrieIndex),
		Outbound: b.OutboundToId(outbound),
	})
}

func (b *RoutingMatcherBuilder) AddL4Proto(values consts.L4ProtoType, outbound string) {
	if b.err != nil {
		return
	}
	b.rules = append(b.rules, bpfRouting{
		Type:     uint32(consts.RoutingType_L4Proto),
		Value:    uint32(values),
		Outbound: b.OutboundToId(outbound),
	})
}

func (b *RoutingMatcherBuilder) AddIpVersion(values consts.IpVersion, outbound string) {
	if b.err != nil {
		return
	}
	b.rules = append(b.rules, bpfRouting{
		Type:     uint32(consts.RoutingType_IpVersion),
		Value:    uint32(values),
		Outbound: b.OutboundToId(outbound),
	})
}

func (b *RoutingMatcherBuilder) AddFinal(outbound string) {
	if b.err != nil {
		return
	}
	b.Final = outbound
	b.rules = append(b.rules, bpfRouting{
		Type:     uint32(consts.RoutingType_Final),
		Outbound: b.OutboundToId(outbound),
	})
}

func (b *RoutingMatcherBuilder) Build() (err error) {
	if b.err != nil {
		return b.err
	}
	// Update lpm_array_map.
	for i, cidrs := range b.SimulatedLpmTries {
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
		// ebpf.Map cannot be BatchUpdate
		if err = b.bpf.LpmArrayMap.Update(uint32(i), m, ebpf.UpdateAny); err != nil {
			m.Close()
			return fmt.Errorf("Update: %w", err)
		}
		m.Close()
	}
	// Write routings.
	// Final rule MUST be the last.
	if b.rules[len(b.rules)-1].Type != uint32(consts.RoutingType_Final) {
		b.err = fmt.Errorf("final rule MUST be the last")
		return b.err
	}
	routingsLen := uint32(len(b.rules))
	routingsKeys := common.ARangeU32(routingsLen)
	if _, err = b.bpf.RoutingMap.BatchUpdate(routingsKeys, b.rules, &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		return fmt.Errorf("BatchUpdate: %w", err)
	}
	return nil
}
