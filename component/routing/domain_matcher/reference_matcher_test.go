/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

type referenceDomainSet struct {
	key       consts.RoutingDomainKey
	ruleIndex int
	patterns  []string
	regexps   []*regexp.Regexp
}

type referenceMatcher struct {
	bitLength int
	sets      []referenceDomainSet
}

func newReferenceMatcher(bitLength int, sets []routing.DomainSet) (*referenceMatcher, error) {
	matcher := &referenceMatcher{
		bitLength: bitLength,
		sets:      make([]referenceDomainSet, 0, len(sets)),
	}
	for _, set := range sets {
		compiled := referenceDomainSet{
			key:       set.Key,
			ruleIndex: set.RuleIndex,
			patterns:  make([]string, len(set.Domains)),
		}
		for i, pattern := range set.Domains {
			if set.Key == consts.RoutingDomainKey_Regex {
				re, err := regexp.Compile(pattern)
				if err != nil {
					return nil, fmt.Errorf("compile reference regexp %q: %w", pattern, err)
				}
				compiled.regexps = append(compiled.regexps, re)
				continue
			}
			compiled.patterns[i] = strings.ToLower(pattern)
		}
		matcher.sets = append(matcher.sets, compiled)
	}
	return matcher, nil
}

func (m *referenceMatcher) MatchDomainBitmap(domain string) []uint32 {
	bitmap := make([]uint32, (m.bitLength+31)/32)
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, set := range m.sets {
		matched := false
		for i, pattern := range set.patterns {
			switch set.key {
			case consts.RoutingDomainKey_Full:
				matched = domain == pattern
			case consts.RoutingDomainKey_Suffix:
				if strings.HasPrefix(pattern, ".") {
					matched = strings.HasSuffix(domain, pattern)
				} else {
					matched = domain == pattern || strings.HasSuffix(domain, "."+pattern)
				}
			case consts.RoutingDomainKey_Keyword:
				matched = strings.Contains(domain, pattern)
			case consts.RoutingDomainKey_Regex:
				matched = set.regexps[i].MatchString(domain)
			}
			if matched {
				bitmap[set.ruleIndex/32] |= 1 << (set.ruleIndex % 32)
				break
			}
		}
	}
	return bitmap
}
