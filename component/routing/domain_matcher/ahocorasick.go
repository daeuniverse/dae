/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, v2rayA Organization <team@v2raya.org>
 */

package domain_matcher

import (
	"fmt"
	"github.com/cloudflare/ahocorasick"
	"github.com/v2rayA/dae/common/consts"
	"regexp"
	"strings"
)

type Ahocorasick struct {
	validIndexes       []int
	validRegexpIndexes []int
	matchers           []*ahocorasick.Matcher
	regexp             [][]*regexp.Regexp

	toBuild [][][]byte
	err     error
}

func NewAhocorasick(bitLength int) *Ahocorasick {
	return &Ahocorasick{
		matchers: make([]*ahocorasick.Matcher, bitLength),
		toBuild:  make([][][]byte, bitLength),
		regexp:   make([][]*regexp.Regexp, bitLength),
	}
}
func (n *Ahocorasick) AddSet(bitIndex int, patterns []string, typ consts.RoutingDomainKey) {
	if n.err != nil {
		return
	}
	switch typ {
	case consts.RoutingDomainKey_Full:
		for _, d := range patterns {
			n.toBuild[bitIndex] = append(n.toBuild[bitIndex], []byte("^"+d+"$"))
		}
	case consts.RoutingDomainKey_Suffix:
		for _, d := range patterns {
			n.toBuild[bitIndex] = append(n.toBuild[bitIndex], []byte("."+strings.TrimPrefix(d, ".")+"$"))
			n.toBuild[bitIndex] = append(n.toBuild[bitIndex], []byte("^"+d+"$"))
		}
	case consts.RoutingDomainKey_Keyword:
		for _, d := range patterns {
			n.toBuild[bitIndex] = append(n.toBuild[bitIndex], []byte(d))
		}
	case consts.RoutingDomainKey_Regex:
		for _, d := range patterns {
			r, err := regexp.Compile(d)
			if err != nil {
				n.err = fmt.Errorf("failed to compile regex: %v", d)
				return
			}
			n.regexp[bitIndex] = append(n.regexp[bitIndex], r)
		}
	default:
		n.err = fmt.Errorf("unknown RoutingDomainKey: %v", typ)
		return
	}
}
func (n *Ahocorasick) MatchDomainBitmap(domain string) (bitmap []uint32) {
	N := len(n.matchers) / 32
	if len(n.matchers)%32 != 0 {
		N++
	}
	bitmap = make([]uint32, N)
	if strings.ContainsAny(domain, "^$") {
		return bitmap
	}
	domain = "^" + strings.ToLower(strings.TrimSuffix(domain, ".")) + "$"
	for _, i := range n.validIndexes {
		if hits := n.matchers[i].MatchThreadSafe([]byte(domain)); len(hits) > 0 {
			bitmap[i/32] |= 1 << (i % 32)
		}
	}
	for _, i := range n.validRegexpIndexes {
		for _, r := range n.regexp[i] {
			if r.MatchString(domain) {
				bitmap[i/32] |= 1 << (i % 32)
				break
			}
		}
	}
	return bitmap
}
func (n *Ahocorasick) Build() error {
	if n.err != nil {
		return n.err
	}
	n.validIndexes = make([]int, 0, len(n.toBuild)/8)
	for i, toBuild := range n.toBuild {
		if len(toBuild) == 0 {
			continue
		}
		n.matchers[i] = ahocorasick.NewMatcher(toBuild)
		n.validIndexes = append(n.validIndexes, i)
	}
	// Release it.
	n.toBuild = nil
	return nil
}
