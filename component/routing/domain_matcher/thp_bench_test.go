/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var benchDisableTHP = flag.Bool("disable-thp", false,
	"apply prctl(PR_SET_THP_DISABLE) before running, mirroring disable_thp: true")

// The disable_thp default claims to trade RSS for matcher throughput without
// any measurement behind either side. This benchmark provides the measurement:
// run it twice on a THP-capable host and compare.
//
//	echo always > /sys/kernel/mm/transparent_hugepage/enabled
//	go test -bench MatchDomainBitmapTHP -benchtime 2s ./component/routing/domain_matcher/
//	go test -bench MatchDomainBitmapTHP -benchtime 2s ./component/routing/domain_matcher/ -disable-thp
//
// The flag applies the same prctl(PR_SET_THP_DISABLE) that disable_thp uses,
// so the two runs reproduce the two config settings exactly.
//
// Measured 2026-07 on i7-14650HX under THP=madvise (Go allocates without
// MADV_HUGEPAGE, so neither arm receives huge pages): both arms are
// statistically identical at ~8.7µs/op over 131072 suffixes. That is the
// expected null result for madvise hosts and is why disable_thp defaults to
// false — on such hosts the knob changes nothing, and on THP=always hosts
// neither its RSS benefit nor its dTLB cost has been demonstrated, so dae
// leaves kernel policy alone until a run of this benchmark on a THP=always
// host shows otherwise.
func TestMain(m *testing.M) {
	flag.Parse()
	if *benchDisableTHP {
		if err := unix.Prctl(unix.PR_SET_THP_DISABLE, 1, 0, 0, 0); err != nil {
			fmt.Fprintf(os.Stderr, "PR_SET_THP_DISABLE failed: %v\n", err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

// syntheticSuffixes approximates a full geosite ruleset: enough distinct
// suffixes that the built automaton spans tens of megabytes and every lookup
// takes dTLB misses on cold pages — the access pattern THP is supposed to help.
func syntheticSuffixes(n int) []string {
	suffixes := make([]string, 0, n)
	for i := range n {
		suffixes = append(suffixes, fmt.Sprintf("host-%06d.example-%03d.com", i, i%997))
	}
	return suffixes
}

func BenchmarkMatchDomainBitmapTHP(b *testing.B) {
	logger := logrus.New()
	logger.SetOutput(discardWriter{})

	const ruleBits = 8
	const domainsPerBit = 16384 // 8 * 16384 = 131072 suffixes total
	matcher := NewAhocorasickSlimtrie(logger, ruleBits)
	all := syntheticSuffixes(ruleBits * domainsPerBit)
	for bit := range ruleBits {
		matcher.AddSet(bit, all[bit*domainsPerBit:(bit+1)*domainsPerBit], consts.RoutingDomainKey_Suffix)
	}
	if err := matcher.Build(); err != nil {
		b.Fatalf("Build() error = %v", err)
	}

	// Queries mix hits (subdomains of registered suffixes) and misses spread
	// across the automaton so consecutive iterations do not stay in cache.
	queries := make([]string, 0, 4096)
	for i := range 2048 {
		idx := (i * 65537) % len(all)
		queries = append(queries, "www."+all[idx])
		queries = append(queries, fmt.Sprintf("miss-%06d.not-registered-%03d.org", idx, i%997))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		matcher.MatchDomainBitmap(queries[i%len(queries)])
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
