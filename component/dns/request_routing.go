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
	"github.com/sirupsen/logrus"
	"golang.org/x/net/dns/dnsmessage"
	"strconv"
)

type RequestMatcherBuilder struct {
	log                *logrus.Logger
	upstreamName2Id    map[string]uint8
	simulatedDomainSet []routing.DomainSet
	fallback           *routing.Outbound
	rules              []requestMatchSet
}

func NewRequestMatcherBuilder(log *logrus.Logger, rules []*config_parser.RoutingRule, upstreamName2Id map[string]uint8, fallback config.FunctionOrString) (b *RequestMatcherBuilder, err error) {
	b = &RequestMatcherBuilder{log: log, upstreamName2Id: upstreamName2Id}
	rulesBuilder := routing.NewRulesBuilder(log)
	rulesBuilder.RegisterFunctionParser(consts.Function_QName, routing.PlainParserFactory(b.addQName))
	rulesBuilder.RegisterFunctionParser(consts.Function_QType, TypeParserFactory(b.addQType))
	if err = rulesBuilder.Apply(rules); err != nil {
		return nil, err
	}

	if err = b.addFallback(fallback); err != nil {
		return nil, err
	}

	return b, nil
}

func (b *RequestMatcherBuilder) upstreamToId(upstream string) (upstreamId consts.DnsRequestOutboundIndex, err error) {
	switch upstream {
	case consts.DnsRequestOutboundIndex_AsIs.String():
		upstreamId = consts.DnsRequestOutboundIndex_AsIs
	case consts.DnsRequestOutboundIndex_LogicalAnd.String():
		upstreamId = consts.DnsRequestOutboundIndex_LogicalAnd
	case consts.DnsRequestOutboundIndex_LogicalOr.String():
		upstreamId = consts.DnsRequestOutboundIndex_LogicalOr
	default:
		_upstreamId, ok := b.upstreamName2Id[upstream]
		if !ok {
			return 0, fmt.Errorf("upstream %v not found; please define it in section \"dns.upstream\"", strconv.Quote(upstream))
		}
		upstreamId = consts.DnsRequestOutboundIndex(_upstreamId)
	}
	return upstreamId, nil
}

func (b *RequestMatcherBuilder) addQName(f *config_parser.Function, key string, values []string, upstream *routing.Outbound) (err error) {
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
	b.rules = append(b.rules, requestMatchSet{
		Type:     consts.MatchType_DomainSet,
		Not:      f.Not,
		Upstream: uint8(upstreamId),
	})
	return nil
}

func (b *RequestMatcherBuilder) addQType(f *config_parser.Function, values []dnsmessage.Type, upstream *routing.Outbound) (err error) {
	for i, value := range values {
		upstreamName := consts.OutboundLogicalOr.String()
		if i == len(values)-1 {
			upstreamName = upstream.Name
		}
		upstreamId, err := b.upstreamToId(upstreamName)
		if err != nil {
			return err
		}
		b.rules = append(b.rules, requestMatchSet{
			Type:     consts.MatchType_QType,
			Value:    uint16(value),
			Not:      f.Not,
			Upstream: uint8(upstreamId),
		})
	}
	return nil
}

func (b *RequestMatcherBuilder) addFallback(fallbackOutbound config.FunctionOrString) (err error) {
	upstream, err := routing.ParseOutbound(config.FunctionOrStringToFunction(fallbackOutbound))
	if err != nil {
		return err
	}
	upstreamId, err := b.upstreamToId(upstream.Name)
	if err != nil {
		return err
	}
	b.rules = append(b.rules, requestMatchSet{
		Type:     consts.MatchType_Fallback,
		Upstream: uint8(upstreamId),
	})
	return nil
}

func (b *RequestMatcherBuilder) Build() (matcher *RequestMatcher, err error) {
	var m RequestMatcher
	// Build domainMatcher
	m.domainMatcher = domain_matcher.NewAhocorasickSlimtrie(b.log, consts.MaxMatchSetLen)
	for _, domains := range b.simulatedDomainSet {
		m.domainMatcher.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err = m.domainMatcher.Build(); err != nil {
		return nil, err
	}

	// Write routings.
	// Fallback rule MUST be the last.
	if b.rules[len(b.rules)-1].Type != consts.MatchType_Fallback {
		return nil, fmt.Errorf("fallback rule MUST be the last")
	}
	m.matches = b.rules

	return &m, nil
}

type RequestMatcher struct {
	domainMatcher routing.DomainMatcher // All domain matchSets use one DomainMatcher.

	matches []requestMatchSet
}

type requestMatchSet struct {
	Value    uint16
	Not      bool
	Type     consts.MatchType
	Upstream uint8
}

func (m *RequestMatcher) Match(
	qName string,
	qType dnsmessage.Type,
) (upstreamIndex consts.DnsRequestOutboundIndex, err error) {
	var domainMatchBitmap []uint32
	if qName != "" {
		domainMatchBitmap = m.domainMatcher.MatchDomainBitmap(qName)
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
		case consts.MatchType_QType:
			if qType == dnsmessage.Type(match.Value) {
				goodSubrule = true
			}
		case consts.MatchType_Fallback:
			goodSubrule = true
		default:
			return 0, fmt.Errorf("unknown match type: %v", match.Type)
		}
	beforeNextLoop:
		upstream := consts.DnsRequestOutboundIndex(match.Upstream)
		if upstream != consts.DnsRequestOutboundIndex_LogicalOr {
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

		if upstream&consts.DnsRequestOutboundIndex_LogicalMask !=
			consts.DnsRequestOutboundIndex_LogicalMask {
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
