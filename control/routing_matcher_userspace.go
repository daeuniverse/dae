/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"net"
)

type RoutingMatcher struct {
	lpmArrayMap   *ebpf.Map
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
	mac []byte,
) (outboundIndex consts.OutboundIndex, mark uint32, err error) {
	if len(sourceAddr) != net.IPv6len || len(destAddr) != net.IPv6len || len(mac) != net.IPv6len {
		return 0, 0, fmt.Errorf("bad address length")
	}
	lpmKeys := make([]*_bpfLpmKey, consts.MatchType_Mac+1)
	lpmKeys[consts.MatchType_IpSet] = &_bpfLpmKey{
		PrefixLen: 128,
		Data:      common.Ipv6ByteSliceToUint32Array(destAddr),
	}
	lpmKeys[consts.MatchType_SourceIpSet] = &_bpfLpmKey{
		PrefixLen: 128,
		Data:      common.Ipv6ByteSliceToUint32Array(sourceAddr),
	}
	lpmKeys[consts.MatchType_Mac] = &_bpfLpmKey{
		PrefixLen: 128,
		Data:      common.Ipv6ByteSliceToUint32Array(mac),
	}
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
			var lpm *ebpf.Map
			if err = m.lpmArrayMap.Lookup(lpmIndex, &lpm); err != nil {
				//logrus.Debugln("m.lpmArrayMap.Lookup:", err)
				break
			}
			var v uint32
			if err = lpm.Lookup(*lpmKeys[int(match.Type)], &v); err != nil {
				_ = lpm.Close()
				//logrus.Debugln("lpm.Lookup:", err, lpmKeys[int(match.Type)], match.Type, destAddr)
				break
			}
			_ = lpm.Close()
			goodSubrule = true
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
		case consts.MatchType_Fallback:
			goodSubrule = true
		default:
			return 0, 0, fmt.Errorf("unknown match type: %v", match.Type)
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
				return outbound, match.Mark, nil
			}
			badRule = false
		}
	}
	return 0, 0, fmt.Errorf("no match set hit")
}
