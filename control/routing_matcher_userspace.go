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

	matches []bpfMatchSet
}

// Match is modified from kern/tproxy.c; please keep sync.
func (m *RoutingMatcher) Match(
	sourceAddr []byte,
	destAddr []byte,
	sourcePort uint16,
	destPort uint16,
	ipVersion consts.IpVersionType,
	l4proto consts.L4ProtoType,
	domain string,
	processName [16]uint8,
	ifindex uint32,
	tos uint8,
	mac []byte,
) (outboundIndex consts.OutboundIndex, mark uint32, must bool, err error) {
	if len(sourceAddr) != net.IPv6len || len(destAddr) != net.IPv6len || len(mac) != net.IPv6len {
		return 0, 0, false, fmt.Errorf("bad address length")
	}

	bin128s := make([]string, consts.MatchType_Mac+1)
	bin128s[consts.MatchType_IpSet] = trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(*(*[16]byte)(destAddr)), 128))
	bin128s[consts.MatchType_SourceIpSet] = trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(*(*[16]byte)(sourceAddr)), 128))
	bin128s[consts.MatchType_Mac] = trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(*(*[16]byte)(mac)), 128))

	var domainMatchBitmap []uint32
	if domain != "" {
		domainMatchBitmap = m.domainMatcher.MatchDomainBitmap(domain)
	}

	goodSubrule := false
	badRule := false
	for i, match := range m.matches {
		if badRule || goodSubrule {
			goto beforeNextLoop
		}
		switch consts.MatchType(match.Type) {
		case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
			lpmIndex := uint32(binary.LittleEndian.Uint16(match.Value[:]))
			m := m.lpmMatcher[lpmIndex]
			if m.HasPrefix(bin128s[match.Type]) {
				goodSubrule = true
			}
		case consts.MatchType_DomainSet:
			if domainMatchBitmap != nil && (domainMatchBitmap[i/32]>>(i%32))&1 > 0 {
				goodSubrule = true
			}
		case consts.MatchType_Port:
			portStart, portEnd := ParsePortRange(match.Value[:])
			if destPort >= portStart &&
				destPort <= portEnd {
				goodSubrule = true
			}
		case consts.MatchType_SourcePort:
			portStart, portEnd := ParsePortRange(match.Value[:])
			if sourcePort >= portStart &&
				sourcePort <= portEnd {
				goodSubrule = true
			}
		case consts.MatchType_IpVersion:
			// LittleEndian
			if ipVersion&consts.IpVersionType(match.Value[0]) > 0 {
				goodSubrule = true
			}
		case consts.MatchType_L4Proto:
			// LittleEndian
			if l4proto&consts.L4ProtoType(match.Value[0]) > 0 {
				goodSubrule = true
			}
		case consts.MatchType_ProcessName:
			if processName[0] != 0 && match.Value == processName {
				goodSubrule = true
			}
		case consts.MatchType_IfIndex:
			if ifindex == binary.LittleEndian.Uint32(match.Value[:]) {
				goodSubrule = true
			}
		case consts.MatchType_Dscp:
			if tos == match.Value[0] {
				goodSubrule = true
			}
		case consts.MatchType_Fallback:
			goodSubrule = true
		default:
			return 0, 0, false, fmt.Errorf("unknown match type: %v", match.Type)
		}
	beforeNextLoop:
		outbound := consts.OutboundIndex(match.Outbound)
		if outbound != consts.OutboundLogicalOr {
			// This match_set reaches the end of subrule.
			// We are now at end of rule, or next match_set belongs to another
			// subrule.

			if goodSubrule == match.Not {
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
				if must {
					match.Must = true
				}
				return outbound, match.Mark, match.Must, nil
			}
			badRule = false
		}
	}
	return 0, 0, false, fmt.Errorf("no match set hit")
}
