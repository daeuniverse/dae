/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"fmt"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"regexp"
	"strings"
)

type Bruteforce struct {
	simulatedDomainSet []routing.DomainSet
	err                error
}

func NewBruteforce(bitLength int) *Bruteforce {
	return &Bruteforce{
		simulatedDomainSet: make([]routing.DomainSet, bitLength),
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
	for _, s := range n.simulatedDomainSet {
		for _, d := range s.Domains {
			var hit bool
			switch s.Key {
			case consts.RoutingDomainKey_Suffix:
				if domain == d || strings.HasSuffix(domain, "."+strings.TrimPrefix(d, ".")) {
					hit = true
				}
			case consts.RoutingDomainKey_Full:
				if strings.EqualFold(domain, d) {
					hit = true
				}
			case consts.RoutingDomainKey_Keyword:
				if strings.Contains(strings.ToLower(domain), strings.ToLower(d)) {
					hit = true
				}
			case consts.RoutingDomainKey_Regex:
				if regexp.MustCompile(d).MatchString(strings.ToLower(domain)) {
					hit = true
				}
			}
			if hit {
				//logrus.Traceln(d, s.Key, "matched given", domain)
				bitmap[s.RuleIndex/32] |= 1 << (s.RuleIndex % 32)
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
	return nil
}
