/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"fmt"
	"github.com/daeuniverse/dae/common/consts"
	"regexp"
	"strings"
)

type GoRegexpNfa struct {
	validIndexes []int
	nfa          []*regexp.Regexp
	toBuild      [][]string
	err          error
}

func NewGoRegexpNfa(bitLength int) *GoRegexpNfa {
	return &GoRegexpNfa{
		nfa:     make([]*regexp.Regexp, bitLength),
		toBuild: make([][]string, bitLength),
	}
}
func (n *GoRegexpNfa) AddSet(bitIndex int, patterns []string, typ consts.RoutingDomainKey) {
	if n.err != nil {
		return
	}
	switch typ {
	case consts.RoutingDomainKey_Full:
		for _, d := range patterns {
			n.toBuild[bitIndex] = append(n.toBuild[bitIndex], "^"+d+"$")
		}
	case consts.RoutingDomainKey_Suffix:
		for _, d := range patterns {
			n.toBuild[bitIndex] = append(n.toBuild[bitIndex], "."+strings.TrimPrefix(d, ".")+"$")
			n.toBuild[bitIndex] = append(n.toBuild[bitIndex], "^"+d+"$")
		}
	case consts.RoutingDomainKey_Keyword:
		for _, d := range patterns {
			n.toBuild[bitIndex] = append(n.toBuild[bitIndex], d)
		}
	case consts.RoutingDomainKey_Regex:
		for _, d := range patterns {
			// Check if it is a valid regexp.
			if _, err := regexp.Compile(d); err != nil {
				n.err = fmt.Errorf("failed to compile regex: %v", d)
				return
			}
			n.toBuild[bitIndex] = append(n.toBuild[bitIndex], d)
		}
	default:
		n.err = fmt.Errorf("unknown RoutingDomainKey: %v", typ)
		return
	}
}
func (n *GoRegexpNfa) MatchDomainBitmap(domain string) (bitmap []uint32) {
	N := len(n.nfa) / 32
	if len(n.nfa)%32 != 0 {
		N++
	}
	bitmap = make([]uint32, N)
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, i := range n.validIndexes {
		if n.nfa[i].MatchString(domain) {
			bitmap[i/32] |= 1 << (i % 32)
		}
	}
	return bitmap
}
func (n *GoRegexpNfa) Build() error {
	if n.err != nil {
		return n.err
	}
	n.validIndexes = make([]int, 0, len(n.toBuild)/8)
	for i, toBuild := range n.toBuild {
		if len(toBuild) == 0 {
			continue
		}
		r, err := regexp.Compile(strings.Join(toBuild, "|"))
		if err != nil {
			return fmt.Errorf("failed to build NFA: %w", err)
		}
		n.nfa[i] = r
		n.validIndexes = append(n.validIndexes, i)
	}
	// Release it.
	n.toBuild = nil
	return nil
}
