/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/trie"
)

type RoutingMatcher struct {
	lpmMatcher    []*trie.Trie
	domainMatcher routing.DomainMatcher // All domain matchSets use one DomainMatcher.

	compiledMatches []compiledRoutingMatch
}

type compiledRoutingMatch struct {
	matchType consts.MatchType
	outbound  consts.OutboundIndex
	not       bool
	mark      uint32
	must      bool

	lpmIndex  uint32
	portStart uint16
	portEnd   uint16
	mask      uint8
	pname     [16]uint8
	dscp      uint8
}

func compileRoutingMatch(match bpfMatchSet) (compiledRoutingMatch, error) {
	compiled := compiledRoutingMatch{
		matchType: consts.MatchType(match.Type),
		outbound:  consts.OutboundIndex(match.Outbound),
		not:       match.Not,
		mark:      match.Mark,
		must:      match.Must,
	}

	switch compiled.matchType {
	case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
		compiled.lpmIndex = binary.LittleEndian.Uint32(match.Value[:4])
	case consts.MatchType_Port, consts.MatchType_SourcePort:
		compiled.portStart, compiled.portEnd = ParsePortRange(match.Value[:])
	case consts.MatchType_IpVersion, consts.MatchType_L4Proto:
		compiled.mask = match.Value[0]
	case consts.MatchType_ProcessName:
		compiled.pname = match.Value
	case consts.MatchType_Dscp:
		compiled.dscp = match.Value[0]
	case consts.MatchType_DomainSet, consts.MatchType_Fallback:
		// No extra decode fields.
	default:
		return compiledRoutingMatch{}, fmt.Errorf("unknown match type: %v", match.Type)
	}

	return compiled, nil
}

func compileRoutingMatches(matches []bpfMatchSet) ([]compiledRoutingMatch, error) {
	compiled := make([]compiledRoutingMatch, 0, len(matches))
	for _, match := range matches {
		c, err := compileRoutingMatch(match)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, c)
	}
	return compiled, nil
}

// Match is modified from kern/tproxy.c; please keep sync.
func (m *RoutingMatcher) Match(
	sourceAddr [16]uint8,
	destAddr [16]uint8,
	sourcePort uint16,
	destPort uint16,
	ipVersion consts.IpVersionType,
	l4proto consts.L4ProtoType,
	domain string,
	processName [16]uint8,
	tos uint8,
	mac [16]uint8,
) (outboundIndex consts.OutboundIndex, mark uint32, must bool, err error) {
	if len(sourceAddr) != net.IPv6len || len(destAddr) != net.IPv6len || len(mac) != net.IPv6len {
		return 0, 0, false, fmt.Errorf("bad address length")
	}

	ipSetBin := trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(destAddr), 128))
	sourceIpSetBin := trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(sourceAddr), 128))
	macBin := trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(mac), 128))

	var domainMatchBitmap []uint32
	if domain != "" {
		domainMatchBitmap = m.domainMatcher.MatchDomainBitmap(domain)
	}

	matches := m.compiledMatches
	if len(matches) == 0 {
		return 0, 0, false, fmt.Errorf("no compiled routing match set")
	}

	goodSubrule := false
	badRule := false
	for i, match := range matches {
		if badRule || goodSubrule {
			goto beforeNextLoop
		}
		switch match.matchType {
		case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
			lpmIndex := int(match.lpmIndex)
			if lpmIndex < 0 || lpmIndex >= len(m.lpmMatcher) {
				return 0, 0, false, fmt.Errorf("bad lpm index: %d", lpmIndex)
			}
			lpm := m.lpmMatcher[lpmIndex]
			var targetBin string
			switch match.matchType {
			case consts.MatchType_IpSet:
				targetBin = ipSetBin
			case consts.MatchType_SourceIpSet:
				targetBin = sourceIpSetBin
			case consts.MatchType_Mac:
				targetBin = macBin
			}
			if lpm.HasPrefix(targetBin) {
				goodSubrule = true
			}
		case consts.MatchType_DomainSet:
			if domainMatchBitmap != nil &&
				i/32 < len(domainMatchBitmap) &&
				(domainMatchBitmap[i/32]>>(i%32))&1 > 0 {
				goodSubrule = true
			}
		case consts.MatchType_Port:
			if destPort >= match.portStart &&
				destPort <= match.portEnd {
				goodSubrule = true
			}
		case consts.MatchType_SourcePort:
			if sourcePort >= match.portStart &&
				sourcePort <= match.portEnd {
				goodSubrule = true
			}
		case consts.MatchType_IpVersion:
			if ipVersion&consts.IpVersionType(match.mask) > 0 {
				goodSubrule = true
			}
		case consts.MatchType_L4Proto:
			if l4proto&consts.L4ProtoType(match.mask) > 0 {
				goodSubrule = true
			}
		case consts.MatchType_ProcessName:
			if processName[0] != 0 && match.pname == processName {
				goodSubrule = true
			}
		case consts.MatchType_Dscp:
			if tos == match.dscp {
				goodSubrule = true
			}
		case consts.MatchType_Fallback:
			goodSubrule = true
		default:
			return 0, 0, false, fmt.Errorf("unknown match type: %v", match.matchType)
		}
	beforeNextLoop:
		outbound := match.outbound
		if outbound != consts.OutboundLogicalOr {
			// This match_set reaches the end of subrule.
			// We are now at end of rule, or next match_set belongs to another
			// subrule.

			if goodSubrule == match.not {
				// This subrule does not hit.
				badRule = true
			}

			// Reset goodSubrule.
			goodSubrule = false
		}

		if outbound&consts.OutboundLogicalMask !=
			consts.OutboundLogicalMask {
			// Tail of a rule (line).
			// Decide whether to hit.
			if !badRule {
				if outbound == consts.OutboundMustRules {
					must = true
					continue
				}
				return outbound, match.mark, match.must || must, nil
			}
			badRule = false
		}
	}
	return 0, 0, false, fmt.Errorf("no match set hit")
}
