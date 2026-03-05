/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"encoding/binary"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func BenchmarkRewriteKernRulesWithRingLpmIndex(b *testing.B) {
	maxEntries := uint32(consts.MaxMatchSetLen)
	allocStartIdx := maxEntries - 1

	makeLpmRule := func(matchType consts.MatchType, lpmIdx uint32) bpfMatchSet {
		r := bpfMatchSet{Type: uint8(matchType)}
		binary.LittleEndian.PutUint32(r.Value[:4], lpmIdx)
		return r
	}

	benchmarks := []struct {
		name  string
		rules []bpfMatchSet
	}{
		{"Small_10Rules", make([]bpfMatchSet, 10)},
		{"Medium_100Rules", make([]bpfMatchSet, 100)},
		{"Large_1000Rules", make([]bpfMatchSet, 1000)},
		{"VeryLarge_10000Rules", make([]bpfMatchSet, 10000)},
	}

	for _, bm := range benchmarks {
		for i := range bm.rules {
			switch i % 4 {
			case 0:
				bm.rules[i] = makeLpmRule(consts.MatchType_IpSet, uint32(i%100))
			case 1:
				bm.rules[i] = makeLpmRule(consts.MatchType_SourceIpSet, uint32(i%100))
			case 2:
				bm.rules[i] = makeLpmRule(consts.MatchType_Mac, uint32(i%100))
			default:
				bm.rules[i] = bpfMatchSet{Type: uint8(consts.MatchType_Port)}
			}
		}
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := rewriteKernRulesWithRingLpmIndex(bm.rules, allocStartIdx, 100)
				if err != nil {
					b.Fatalf("rewriteKernRulesWithRingLpmIndex: %v", err)
				}
			}
		})
	}
}

func BenchmarkRewriteKernRulesWithRingLpmIndex_ReuseBuffer(b *testing.B) {
	maxEntries := uint32(consts.MaxMatchSetLen)
	allocStartIdx := maxEntries - 1

	makeLpmRule := func(matchType consts.MatchType, lpmIdx uint32) bpfMatchSet {
		r := bpfMatchSet{Type: uint8(matchType)}
		binary.LittleEndian.PutUint32(r.Value[:4], lpmIdx)
		return r
	}

	ruleSets := []struct {
		name  string
		rules []bpfMatchSet
	}{
		{"Small_10Rules", make([]bpfMatchSet, 10)},
		{"Medium_100Rules", make([]bpfMatchSet, 100)},
		{"Large_1000Rules", make([]bpfMatchSet, 1000)},
		{"VeryLarge_10000Rules", make([]bpfMatchSet, 10000)},
	}

	for _, rs := range ruleSets {
		for i := range rs.rules {
			switch i % 4 {
			case 0:
				rs.rules[i] = makeLpmRule(consts.MatchType_IpSet, uint32(i%100))
			case 1:
				rs.rules[i] = makeLpmRule(consts.MatchType_SourceIpSet, uint32(i%100))
			case 2:
				rs.rules[i] = makeLpmRule(consts.MatchType_Mac, uint32(i%100))
			default:
				rs.rules[i] = bpfMatchSet{Type: uint8(consts.MatchType_Port)}
			}
		}
	}

	for _, rs := range ruleSets {
		b.Run(rs.name, func(b *testing.B) {
			b.ReportAllocs()
			buf := make([]bpfMatchSet, len(rs.rules))
			for i := 0; i < b.N; i++ {
				if len(buf) < len(rs.rules) {
					buf = make([]bpfMatchSet, len(rs.rules))
				}
				buf = buf[:len(rs.rules)]
				maxEntriesLocal := uint32(consts.MaxMatchSetLen)
				lpmCount := uint32(100)

				copy(buf, rs.rules)
				for j, rule := range buf {
					matchType := consts.MatchType(rule.Type)
					switch matchType {
					case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
						oldLpmIndex := binary.LittleEndian.Uint32(rule.Value[:4])
						if oldLpmIndex < lpmCount {
							newLpmIndex := (allocStartIdx + oldLpmIndex) % maxEntriesLocal
							binary.LittleEndian.PutUint32(buf[j].Value[:4], newLpmIndex)
						}
					}
				}
			}
		})
	}
}

func BenchmarkRewriteKernRules_HotReload(b *testing.B) {
	maxEntries := uint32(consts.MaxMatchSetLen)

	makeLpmRule := func(matchType consts.MatchType, lpmIdx uint32) bpfMatchSet {
		r := bpfMatchSet{Type: uint8(matchType)}
		binary.LittleEndian.PutUint32(r.Value[:4], lpmIdx)
		return r
	}

	rules := make([]bpfMatchSet, 500)
	for i := range rules {
		switch i % 4 {
		case 0:
			rules[i] = makeLpmRule(consts.MatchType_IpSet, uint32(i%100))
		case 1:
			rules[i] = makeLpmRule(consts.MatchType_SourceIpSet, uint32(i%100))
		case 2:
			rules[i] = makeLpmRule(consts.MatchType_Mac, uint32(i%100))
		default:
			rules[i] = bpfMatchSet{Type: uint8(consts.MatchType_Port)}
		}
	}

	b.Run("CurrentImplementation", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			allocStartIdx := uint32(i % 1000)
			_, err := rewriteKernRulesWithRingLpmIndex(rules, allocStartIdx, 100)
			if err != nil {
				b.Fatalf("rewriteKernRulesWithRingLpmIndex: %v", err)
			}
		}
	})

	b.Run("WithBufferReuse", func(b *testing.B) {
		b.ReportAllocs()
		buf := make([]bpfMatchSet, len(rules))
		lpmCount := uint32(100)

		for i := 0; i < b.N; i++ {
			allocStartIdx := uint32(i % 1000)
			if len(buf) < len(rules) {
				buf = make([]bpfMatchSet, len(rules))
			}
			buf = buf[:len(rules)]

			copy(buf, rules)
			for j, rule := range buf {
				matchType := consts.MatchType(rule.Type)
				switch matchType {
				case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
					oldLpmIndex := binary.LittleEndian.Uint32(rule.Value[:4])
					if oldLpmIndex < lpmCount {
						newLpmIndex := (allocStartIdx + oldLpmIndex) % maxEntries
						binary.LittleEndian.PutUint32(buf[j].Value[:4], newLpmIndex)
					}
				}
			}
		}
	})
}
