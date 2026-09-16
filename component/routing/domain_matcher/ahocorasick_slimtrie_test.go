/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"math/rand"
	"slices"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/sirupsen/logrus"
)

func TestAhocorasickSlimtrie(t *testing.T) {
	const bitLength = 64
	domainSets := []routing.DomainSet{
		{Key: consts.RoutingDomainKey_Full, RuleIndex: 0, Domains: []string{"Exact.Example"}},
		{Key: consts.RoutingDomainKey_Suffix, RuleIndex: 1, Domains: []string{"Example.COM"}},
		{Key: consts.RoutingDomainKey_Suffix, RuleIndex: 2, Domains: []string{".Internal.TEST"}},
		{Key: consts.RoutingDomainKey_Keyword, RuleIndex: 31, Domains: []string{"GoOgLe"}},
		{Key: consts.RoutingDomainKey_Regex, RuleIndex: 33, Domains: []string{`^api\.[a-z]+\.test$`}},
	}
	reference, err := newReferenceMatcher(bitLength, domainSets)
	if err != nil {
		t.Fatal(err)
	}
	actrie := NewAhocorasickSlimtrie(logrus.New(), bitLength)
	for _, domains := range domainSets {
		actrie.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err = actrie.Build(); err != nil {
		t.Fatal(err)
	}

	r := rand.New(rand.NewSource(200))
	for i := range 10000 {
		sample := differentialDomainSample(r, i)
		want := reference.MatchDomainBitmap(sample)
		got := actrie.MatchDomainBitmap(sample)
		if !slices.Equal(got, want) {
			t.Fatalf("sample %q: MatchDomainBitmap() = %v, want %v", sample, got, want)
		}
	}
}

func differentialDomainSample(r *rand.Rand, iteration int) string {
	label := randomDomainLabel(r, 8)
	var domain string
	switch iteration % 8 {
	case 0:
		domain = "exact.example"
	case 1:
		domain = label + ".example.com"
	case 2:
		domain = "example.com"
	case 3:
		domain = label + ".internal.test"
	case 4:
		domain = "internal.test"
	case 5:
		domain = "www.google-" + label + ".net"
	case 6:
		domain = "api." + label + ".test"
	default:
		domain = label + ".invalid"
	}
	if iteration%3 == 0 {
		domain = randomDomainCase(r, domain)
	}
	if iteration%5 == 0 {
		domain += "."
	}
	return domain
}

func randomDomainLabel(r *rand.Rand, length int) string {
	label := make([]byte, length)
	for i := range label {
		label[i] = 'a' + byte(r.Intn(26))
	}
	return string(label)
}

func randomDomainCase(r *rand.Rand, domain string) string {
	mixed := []byte(domain)
	for i, c := range mixed {
		if c >= 'a' && c <= 'z' && r.Intn(2) == 0 {
			mixed[i] = c - ('a' - 'A')
		}
	}
	return string(mixed)
}

func TestDomainPatternsAreCaseInsensitive(t *testing.T) {
	matcher := NewAhocorasickSlimtrie(logrus.StandardLogger(), 32)
	matcher.AddSet(0, []string{"Example.COM"}, consts.RoutingDomainKey_Full)
	matcher.AddSet(1, []string{"Example.COM"}, consts.RoutingDomainKey_Suffix)
	matcher.AddSet(2, []string{"AmPlE"}, consts.RoutingDomainKey_Keyword)
	if err := matcher.Build(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		domain string
		bit    uint
	}{
		{domain: "EXAMPLE.com.", bit: 0},
		{domain: "www.EXAMPLE.com.", bit: 1},
		{domain: "www.example.net.", bit: 2},
	}
	for _, test := range tests {
		bitmap := matcher.MatchDomainBitmap(test.domain)
		if bitmap[0]&(1<<test.bit) == 0 {
			t.Errorf("MatchDomainBitmap(%q) = %032b, want bit %d", test.domain, bitmap[0], test.bit)
		}
	}
}

func TestAddSetRejectsOutOfBoundsBitIndex(t *testing.T) {
	// An index equal to bitLength used to panic on the toBuildTrie write;
	// it must surface as a Build error instead.
	actrie := NewAhocorasickSlimtrie(logrus.StandardLogger(), 8)
	actrie.AddSet(8, []string{"example.com"}, consts.RoutingDomainKey_Full)
	if err := actrie.Build(); err == nil {
		t.Fatal("Build() error = nil, want out-of-range error for bitIndex == bitLength")
	}

	negative := NewAhocorasickSlimtrie(logrus.StandardLogger(), 8)
	negative.AddSet(-1, []string{"example.com"}, consts.RoutingDomainKey_Suffix)
	if err := negative.Build(); err == nil {
		t.Fatal("Build() error = nil, want out-of-range error for negative bitIndex")
	}
}

func TestMatchDomainBitmapHitReturnsSharedAlias(t *testing.T) {
	actrie := NewAhocorasickSlimtrie(logrus.StandardLogger(), 32)
	actrie.AddSet(0, []string{"example.com"}, consts.RoutingDomainKey_Full)
	if err := actrie.Build(); err != nil {
		t.Fatal(err)
	}
	first := actrie.MatchDomainBitmap("example.com")
	second := actrie.MatchDomainBitmap("example.com")
	if len(first) == 0 || first[0] == 0 {
		t.Fatal("expected a hit bit")
	}
	if &first[0] != &second[0] {
		t.Fatal("hit path cloned the memoized bitmap; callers must treat it as immutable")
	}
}
