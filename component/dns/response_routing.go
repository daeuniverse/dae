/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"fmt"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/routing/domain_matcher"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/trie"
	"github.com/mzz2017/softwind/pkg/zeroalloc/buffer"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/dns/dnsmessage"
	"net/netip"
	"strconv"
	"strings"
)

var ValidCidrChars = trie.NewValidChars([]byte{'0', '1'})

type ResponseMatcherBuilder struct {
	log                *logrus.Logger
	upstreamName2Id    map[string]uint8
	simulatedDomainSet []routing.DomainSet
	ipSet              []*trie.Trie
	fallback           *routing.Outbound
	rules              []responseMatchSet
}

func NewResponseMatcherBuilder(log *logrus.Logger, rules []*config_parser.RoutingRule, upstreamName2Id map[string]uint8, fallback config.FunctionOrString) (b *ResponseMatcherBuilder, err error) {
	b = &ResponseMatcherBuilder{log: log, upstreamName2Id: upstreamName2Id}
	rulesBuilder := routing.NewRulesBuilder(log)
	rulesBuilder.RegisterFunctionParser(consts.Function_QName, routing.PlainParserFactory(b.addQName))
	rulesBuilder.RegisterFunctionParser(consts.Function_QType, TypeParserFactory(b.addQType))
	rulesBuilder.RegisterFunctionParser(consts.Function_Ip, routing.IpParserFactory(b.addIp))
	rulesBuilder.RegisterFunctionParser(consts.Function_Upstream, routing.EmptyKeyPlainParserFactory(b.addUpstream))
	if err = rulesBuilder.Apply(rules); err != nil {
		return nil, err
	}

	if err = b.addFallback(fallback); err != nil {
		return nil, err
	}

	return b, nil
}

func (b *ResponseMatcherBuilder) upstreamToId(upstream string) (upstreamId consts.DnsResponseOutboundIndex, err error) {
	switch upstream {
	case consts.DnsResponseOutboundIndex_Accept.String():
		upstreamId = consts.DnsResponseOutboundIndex_Accept
	case consts.DnsResponseOutboundIndex_Reject.String():
		upstreamId = consts.DnsResponseOutboundIndex_Reject
	case consts.DnsResponseOutboundIndex_LogicalAnd.String():
		upstreamId = consts.DnsResponseOutboundIndex_LogicalAnd
	case consts.DnsResponseOutboundIndex_LogicalOr.String():
		upstreamId = consts.DnsResponseOutboundIndex_LogicalOr
	default:
		_upstreamId, ok := b.upstreamName2Id[upstream]
		if !ok {
			return 0, fmt.Errorf("upstream %v not found; please define it in \"dns.upstream\"", strconv.Quote(upstream))
		}
		upstreamId = consts.DnsResponseOutboundIndex(_upstreamId)
	}
	return upstreamId, nil
}

func prefix2bin128(prefix netip.Prefix) (bin128 string) {
	bits := prefix.Bits()
	if prefix.Addr().Is4() {
		bits += 96
	}
	ip := prefix.Addr().As16()
	buf := buffer.NewBuffer(128)
	defer buf.Put()
loop:
	for i := 0; i < len(ip); i++ {
		for j := 0; j < 8; j++ {
			if (ip[i]>>j)&1 == 1 {
				buf.WriteByte('1')
			} else {
				buf.WriteByte('0')
			}
			bits--
			if bits == 0 {
				break loop
			}
		}
	}
	return buf.String()
}

func (b *ResponseMatcherBuilder) addIp(f *config_parser.Function, cidrs []netip.Prefix, upstream *routing.Outbound) (err error) {
	upstreamId, err := b.upstreamToId(upstream.Name)
	if err != nil {
		return err
	}
	rule := responseMatchSet{
		Value:    uint16(len(b.ipSet)),
		Type:     consts.MatchType_IpSet,
		Not:      f.Not,
		Upstream: uint8(upstreamId),
	}
	var keys []string
	// Convert netip.Prefix -> '0' '1' string
	for _, prefix := range cidrs {
		keys = append(keys, prefix2bin128(prefix))
	}
	t, err := trie.NewTrie(keys, ValidCidrChars)
	if err != nil {
		return err
	}
	b.ipSet = append(b.ipSet, t)
	b.rules = append(b.rules, rule)
	return nil
}

func (b *ResponseMatcherBuilder) addQName(f *config_parser.Function, key string, values []string, upstream *routing.Outbound) (err error) {
	switch consts.RoutingDomainKey(key) {
	case consts.RoutingDomainKey_Regex,
		consts.RoutingDomainKey_Full,
		consts.RoutingDomainKey_Keyword,
		consts.RoutingDomainKey_Suffix:
	default:
		return fmt.Errorf("addQName: unsupported key: %v", key)
	}
	b.simulatedDomainSet = append(b.simulatedDomainSet, routing.DomainSet{
		Key:       consts.RoutingDomainKey(key),
		RuleIndex: len(b.simulatedDomainSet),
		Domains:   values,
	})
	upstreamId, err := b.upstreamToId(upstream.Name)
	if err != nil {
		return err
	}
	b.rules = append(b.rules, responseMatchSet{
		Type:     consts.MatchType_DomainSet,
		Not:      f.Not,
		Upstream: uint8(upstreamId),
	})
	return nil
}

func (b *ResponseMatcherBuilder) addUpstream(f *config_parser.Function, values []string, upstream *routing.Outbound) (err error) {
	for i, value := range values {
		upstreamName := consts.OutboundLogicalOr.String()
		if i == len(values)-1 {
			upstreamName = upstream.Name
		}
		upstreamId, err := b.upstreamToId(upstreamName)
		if err != nil {
			return err
		}
		lastUpstreamId, err := b.upstreamToId(value)
		if err != nil {
			return err
		}
		b.rules = append(b.rules, responseMatchSet{
			Type:     consts.MatchType_Upstream,
			Value:    uint16(lastUpstreamId),
			Not:      f.Not,
			Upstream: uint8(upstreamId),
		})
	}
	return nil
}

func (b *ResponseMatcherBuilder) addQType(f *config_parser.Function, values []dnsmessage.Type, upstream *routing.Outbound) (err error) {
	for i, value := range values {
		upstreamName := consts.OutboundLogicalOr.String()
		if i == len(values)-1 {
			upstreamName = upstream.Name
		}
		upstreamId, err := b.upstreamToId(upstreamName)
		if err != nil {
			return err
		}
		b.rules = append(b.rules, responseMatchSet{
			Type:     consts.MatchType_QType,
			Value:    uint16(value),
			Not:      f.Not,
			Upstream: uint8(upstreamId),
		})
	}
	return nil
}

func (b *ResponseMatcherBuilder) addFallback(fallbackOutbound config.FunctionOrString) (err error) {
	upstream, err := routing.ParseOutbound(config.FunctionOrStringToFunction(fallbackOutbound))
	if err != nil {
		return err
	}
	upstreamId, err := b.upstreamToId(upstream.Name)
	if err != nil {
		return err
	}
	b.rules = append(b.rules, responseMatchSet{
		Type:     consts.MatchType_Fallback,
		Upstream: uint8(upstreamId),
	})
	return nil
}

func (b *ResponseMatcherBuilder) Build() (matcher *ResponseMatcher, err error) {
	var m ResponseMatcher
	// Build domainMatcher.
	m.domainMatcher = domain_matcher.NewAhocorasickSlimtrie(b.log, consts.MaxMatchSetLen)
	for _, domains := range b.simulatedDomainSet {
		m.domainMatcher.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err = m.domainMatcher.Build(); err != nil {
		return nil, err
	}
	// IpSet.
	m.ipSet = b.ipSet

	// Write routings.
	// Fallback rule MUST be the last.
	if b.rules[len(b.rules)-1].Type != consts.MatchType_Fallback {
		return nil, fmt.Errorf("fallback rule MUST be the last")
	}
	m.matches = b.rules

	return &m, nil
}

type ResponseMatcher struct {
	domainMatcher routing.DomainMatcher // All domain matchSets use one DomainMatcher.
	ipSet         []*trie.Trie

	matches []responseMatchSet
}

type responseMatchSet struct {
	Value    uint16
	Not      bool
	Type     consts.MatchType
	Upstream uint8
}

func (m *ResponseMatcher) Match(
	qName string,
	qType dnsmessage.Type,
	ips []netip.Addr,
	upstream consts.DnsRequestOutboundIndex,
) (upstreamIndex consts.DnsResponseOutboundIndex, err error) {
	if qName == "" {
		return 0, fmt.Errorf("qName cannot be empty")
	}
	qName = strings.TrimSuffix(strings.ToLower(qName), ".")
	domainMatchBitmap := m.domainMatcher.MatchDomainBitmap(qName)
	bin128 := make([]string, 0, len(ips))
	for _, ip := range ips {
		bin128 = append(bin128, prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(ip.As16()), 128)))
	}

	goodSubrule := false
	badRule := false
	for i, match := range m.matches {
		if badRule || goodSubrule {
			goto beforeNextLoop
		}
		switch match.Type {
		case consts.MatchType_DomainSet:
			if domainMatchBitmap != nil && (domainMatchBitmap[i/32]>>(i%32))&1 > 0 {
				goodSubrule = true
			}
		case consts.MatchType_IpSet:
			for _, bin128 := range bin128 {
				// Check if any of IP hit the rule.
				if m.ipSet[match.Value].HasPrefix(bin128) {
					goodSubrule = true
					break
				}
			}
		case consts.MatchType_QType:
			if qType == dnsmessage.Type(match.Value) {
				goodSubrule = true
			}
		case consts.MatchType_Upstream:
			if upstream == consts.DnsRequestOutboundIndex(match.Value) {
				goodSubrule = true
			}
		case consts.MatchType_Fallback:
			goodSubrule = true
		default:
			return 0, fmt.Errorf("unknown match type: %v", match.Type)
		}
	beforeNextLoop:
		upstream := consts.DnsResponseOutboundIndex(match.Upstream)
		if upstream != consts.DnsResponseOutboundIndex_LogicalOr {
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

		if upstream&consts.DnsResponseOutboundIndex_LogicalMask !=
			consts.DnsResponseOutboundIndex_LogicalMask {
			// Tail of a rule (line).
			// Decide whether to hit.
			if !badRule {
				return upstream, nil
			}
			badRule = false
		}
	}
	return 0, fmt.Errorf("no match set hit")
}
