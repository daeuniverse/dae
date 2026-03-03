/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"fmt"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"regexp"
	"strings"
)

type compiledDomainSet struct {
	set          routing.DomainSet
	lowerDomains []string
	regexps      []*regexp.Regexp
}

type Bruteforce struct {
	simulatedDomainSet []routing.DomainSet
	compiledDomainSet  []compiledDomainSet
	err                error
}

func NewBruteforce(bitLength int) *Bruteforce {
	return &Bruteforce{
		simulatedDomainSet: make([]routing.DomainSet, bitLength),
		compiledDomainSet:  make([]compiledDomainSet, bitLength),
	}
}
func (n *Bruteforce) AddSet(bitIndex int, patterns []string, typ consts.RoutingDomainKey) {
	if n.err != nil {
		return
	}
	if len(n.simulatedDomainSet[bitIndex].Domains) != 0 {
		n.err = fmt.Errorf("duplicated RuleIndex: %v", bitIndex)
		return
	}
	n.simulatedDomainSet[bitIndex] = routing.DomainSet{
		Key:       typ,
		RuleIndex: bitIndex,
		Domains:   patterns,
	}
}
func (n *Bruteforce) MatchDomainBitmap(domain string) (bitmap []uint32) {
	N := len(n.simulatedDomainSet) / 32
	if len(n.simulatedDomainSet)%32 != 0 {
		N++
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	bitmap = make([]uint32, N)
	for _, s := range n.compiledDomainSet {
		for i, d := range s.set.Domains {
			var hit bool
			switch s.set.Key {
			case consts.RoutingDomainKey_Suffix:
				if domain == d || strings.HasSuffix(domain, "."+strings.TrimPrefix(d, ".")) {
					hit = true
				}
			case consts.RoutingDomainKey_Full:
				if strings.EqualFold(domain, d) {
					hit = true
				}
			case consts.RoutingDomainKey_Keyword:
				if strings.Contains(domain, s.lowerDomains[i]) {
					hit = true
				}
			case consts.RoutingDomainKey_Regex:
				if s.regexps[i].MatchString(domain) {
					hit = true
				}
			}
			if hit {
				//logrus.Traceln(d, s.Key, "matched given", domain)
				bitmap[s.set.RuleIndex/32] |= 1 << (s.set.RuleIndex % 32)
				break
			}
		}
	}
	return bitmap
}
func (n *Bruteforce) Build() error {
	if n.err != nil {
		return n.err
	}
	for i, s := range n.simulatedDomainSet {
		n.compiledDomainSet[i].set = s
		switch s.Key {
		case consts.RoutingDomainKey_Keyword:
			n.compiledDomainSet[i].lowerDomains = make([]string, len(s.Domains))
			for j, d := range s.Domains {
				n.compiledDomainSet[i].lowerDomains[j] = strings.ToLower(d)
			}
		case consts.RoutingDomainKey_Regex:
			n.compiledDomainSet[i].regexps = make([]*regexp.Regexp, len(s.Domains))
			for j, d := range s.Domains {
				r, err := regexp.Compile(d)
				if err != nil {
					return err
				}
				n.compiledDomainSet[i].regexps[j] = r
			}
		}
	}
	return nil
}
