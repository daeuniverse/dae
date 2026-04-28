/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

func TestAhocorasickSlimtrie(t *testing.T) {

	logrus.SetLevel(logrus.TraceLevel)
	simulatedDomainSet, err := getDomain()
	if err != nil {
		if strings.Contains(err.Error(), "geosite.dat: file does not exist") {
			t.Skipf("skip due to missing geosite.dat in test environment: %v", err)
		}
		t.Fatal(err)
	}
	bf := NewBruteforce(consts.MaxMatchSetLen)
	actrie := NewAhocorasickSlimtrie(logrus.StandardLogger(), consts.MaxMatchSetLen)
	for _, domains := range simulatedDomainSet {
		bf.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
		actrie.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err = bf.Build(); err != nil {
		t.Fatal(err)
	}
	if err = actrie.Build(); err != nil {
		t.Fatal(err)
	}

	r := rand.New(rand.NewSource(200))
	for i := range 10000 {
		sample := TestSample[r.Intn(len(TestSample))]
		choice := r.Intn(10)
		switch {
		case choice < 4:
			addN := r.Intn(5)
			buf := make([]byte, addN)
			for i := range buf {
				buf[i] = 'a' + byte(r.Intn('z'-'a'))
			}
			sample = string(buf) + "." + sample
		case choice >= 4 && choice < 6:
			k := r.Intn(len(sample))
			sample = sample[k:]
		default:
		}
		bitmap := bf.MatchDomainBitmap(sample)
		bitmap2 := actrie.MatchDomainBitmap(sample)
		if !slices.Equal(bitmap, bitmap2) {
			t.Fatal(i, sample, bitmap, bitmap2)
		}
	}
}
