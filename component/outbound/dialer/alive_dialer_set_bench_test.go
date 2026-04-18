/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/pkg/fastrand"
)

var benchmarkSelectedDialer *Dialer

func benchmarkAliveDialerSet(size int, weighted bool) *AliveDialerSet {
	dialers := make([]*Dialer, size)
	annotations := make([]*Annotation, size)
	for i := range size {
		dialers[i] = &Dialer{}
		annotation := &Annotation{}
		if weighted && i%10 == 0 {
			annotation.AddWeight = 9
		}
		annotations[i] = annotation
	}
	return NewAliveDialerSet(
		nil,
		"benchmark-group",
		nil,
		0,
		consts.DialerSelectionPolicy_Random,
		dialers,
		annotations,
		func(bool) {},
		true,
	)
}

func benchmarkGetRandFast(set *AliveDialerSet) *Dialer {
	set.mu.Lock()
	defer set.mu.Unlock()
	if len(set.inorderedAliveDialerSet) == 0 {
		return nil
	}
	ind := fastrand.Intn(len(set.inorderedAliveDialerSet))
	return set.inorderedAliveDialerSet[ind]
}

func BenchmarkAliveDialerSet_GetRand(b *testing.B) {
	for _, scenario := range []struct {
		name     string
		weighted bool
	}{
		{name: "default_weights", weighted: false},
		{name: "partial_add_weight", weighted: true},
	} {
		b.Run(scenario.name, func(b *testing.B) {
			for _, size := range []int{10, 100, 1000, 10000, 100000} {
				b.Run(fmt.Sprintf("weighted/%d", size), func(b *testing.B) {
					set := benchmarkAliveDialerSet(size, scenario.weighted)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						benchmarkSelectedDialer = set.GetRand()
					}
				})
				b.Run(fmt.Sprintf("fastrand/%d", size), func(b *testing.B) {
					set := benchmarkAliveDialerSet(size, scenario.weighted)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						benchmarkSelectedDialer = benchmarkGetRandFast(set)
					}
				})
			}
		})
	}
}
