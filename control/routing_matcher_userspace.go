/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
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
	predicateGroups []routingMatcherPredicateGroupSpan

	// needs records which fact strings any compiled rule can consume, so the
	// hot path skips building 128-char binary keys nothing will ever read.
	needs routingMatcherNeeds
}

type routingMatcherNeeds struct {
	ipSetBin     bool
	sourceIPSetB bool
	macBin       bool
	domainBitmap bool
}

func computeRoutingMatcherNeeds(matches []compiledRoutingMatch) routingMatcherNeeds {
	var n routingMatcherNeeds
	for _, m := range matches {
		switch m.matchType {
		case consts.MatchType_IpSet:
			n.ipSetBin = true
		case consts.MatchType_SourceIpSet:
			n.sourceIPSetB = true
		case consts.MatchType_Mac:
			n.macBin = true
		case consts.MatchType_DomainSet:
			n.domainBitmap = true
		}
	}
	return n
}

// routingMatcherPredicateGroupSpan maps one immutable policy predicate group
// to the compiled match operations emitted by the legacy lowerer.
//
// The span is recorded while RulesBuilder invokes the parser. It cannot be
// reconstructed from logical outbound markers because a non-final parameter
// key group can itself end with OutboundLogicalOr.
type routingMatcherPredicateGroupSpan struct {
	name  string
	key   string
	not   bool
	start int
	end   int
}

// routingMatcherFacts is the normalized userspace input shared by the legacy
// matcher loop and the PolicySnapshot predicate-group resolver.
type routingMatcherFacts struct {
	sourceAddr [16]uint8
	destAddr   [16]uint8
	sourcePort uint16
	destPort   uint16
	ipVersion  consts.IpVersionType
	l4proto    consts.L4ProtoType
	domain     string
	pname      [16]uint8
	dscp       uint8
	mac        [16]uint8

	ipSetBin       string
	sourceIPSetBin string
	macBin         string
	domainBitmap   []uint32
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
		not:       match.Not != 0,
		mark:      match.Mark,
		must:      match.Must != 0,
	}

	switch compiled.matchType {
	case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
		compiled.lpmIndex = nativeBpfABI.uint32(match.Value[:4])
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

func (m *RoutingMatcher) newFacts(
	sourceAddr [16]uint8,
	destAddr [16]uint8,
	sourcePort uint16,
	destPort uint16,
	ipVersion consts.IpVersionType,
	l4proto consts.L4ProtoType,
	domain string,
	processName [16]uint8,
	dscp uint8,
	mac [16]uint8,
) (routingMatcherFacts, error) {
	if len(sourceAddr) != net.IPv6len || len(destAddr) != net.IPv6len || len(mac) != net.IPv6len {
		return routingMatcherFacts{}, fmt.Errorf("bad address length")
	}

	facts := routingMatcherFacts{
		sourceAddr: sourceAddr,
		destAddr:   destAddr,
		sourcePort: sourcePort,
		destPort:   destPort,
		ipVersion:  ipVersion,
		l4proto:    l4proto,
		domain:     domain,
		pname:      processName,
		dscp:       dscp,
		mac:        mac,
	}
	// Gated on the compiled rule inventory: Prefix2bin128 churns a 128-byte
	// string per call, so skip keys that no rule reads.
	if m.needs.ipSetBin {
		facts.ipSetBin = trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(destAddr), 128))
	}
	if m.needs.sourceIPSetB {
		facts.sourceIPSetBin = trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(sourceAddr), 128))
	}
	if m.needs.macBin {
		facts.macBin = trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(mac), 128))
	}
	if m.needs.domainBitmap && domain != "" {
		facts.domainBitmap = m.domainMatcher.MatchDomainBitmap(domain)
	}
	return facts, nil
}

// matchCompiledMatch evaluates one positive compiled match operation. Callers
// own group negation and logical composition so this stays identical for the
// legacy matcher loop and PolicySnapshot predicate-group evaluation.
func (m *RoutingMatcher) matchCompiledMatch(index int, match compiledRoutingMatch, facts *routingMatcherFacts) (bool, error) {
	if facts == nil {
		return false, fmt.Errorf("nil routing matcher facts")
	}

	switch match.matchType {
	case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
		lpmIndex := int(match.lpmIndex)
		if lpmIndex < 0 || lpmIndex >= len(m.lpmMatcher) {
			return false, fmt.Errorf("bad lpm index: %d", lpmIndex)
		}
		var targetBin string
		switch match.matchType {
		case consts.MatchType_IpSet:
			targetBin = facts.ipSetBin
		case consts.MatchType_SourceIpSet:
			targetBin = facts.sourceIPSetBin
		case consts.MatchType_Mac:
			targetBin = facts.macBin
		}
		return m.lpmMatcher[lpmIndex].HasPrefix(targetBin), nil
	case consts.MatchType_DomainSet:
		return facts.domainBitmap != nil &&
			index/32 < len(facts.domainBitmap) &&
			(facts.domainBitmap[index/32]>>(index%32))&1 > 0, nil
	case consts.MatchType_Port:
		return facts.destPort >= match.portStart && facts.destPort <= match.portEnd, nil
	case consts.MatchType_SourcePort:
		return facts.sourcePort >= match.portStart && facts.sourcePort <= match.portEnd, nil
	case consts.MatchType_IpVersion:
		return facts.ipVersion&consts.IpVersionType(match.mask) > 0, nil
	case consts.MatchType_L4Proto:
		return facts.l4proto&consts.L4ProtoType(match.mask) > 0, nil
	case consts.MatchType_ProcessName:
		return facts.pname[0] != 0 && match.pname == facts.pname, nil
	case consts.MatchType_Dscp:
		return facts.dscp == match.dscp, nil
	case consts.MatchType_Fallback:
		return true, nil
	default:
		return false, fmt.Errorf("unknown match type: %v", match.matchType)
	}
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
	dscp uint8,
	mac [16]uint8,
) (outboundIndex consts.OutboundIndex, mark uint32, must bool, err error) {
	facts, err := m.newFacts(
		sourceAddr,
		destAddr,
		sourcePort,
		destPort,
		ipVersion,
		l4proto,
		domain,
		processName,
		dscp,
		mac,
	)
	if err != nil {
		return 0, 0, false, err
	}

	matches := m.compiledMatches
	if len(matches) == 0 {
		return 0, 0, false, fmt.Errorf("no compiled routing match set")
	}

	goodSubrule := false
	badRule := false
	for i, match := range matches {
		if !badRule && !goodSubrule {
			matched, matchErr := m.matchCompiledMatch(i, match, &facts)
			if matchErr != nil {
				return 0, 0, false, matchErr
			}
			if matched {
				goodSubrule = true
			}
		}
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
				if outbound == consts.OutboundControlPlaneRouting {
					// Implicit sniff-punt lines exist only in the kernel-space
					// projection: once a connection has been punted and
					// sniffed, userspace must re-route over the remaining
					// rules as if this line did not exist.
					badRule = false
					continue
				}
				return outbound, match.mark, match.must || must, nil
			}
			badRule = false
		}
	}
	return 0, 0, false, fmt.Errorf("no match set hit")
}
