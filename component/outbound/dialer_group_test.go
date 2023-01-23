/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package outbound

import (
	"foo/common/consts"
	"foo/component/outbound/dialer"
	"foo/pkg/logger"
	"github.com/mzz2017/softwind/pkg/fastrand"
	"testing"
	"time"
)

func TestDialerGroup_Select_Fixed(t *testing.T) {
	log := logger.NewLogger(2)
	dialers := []*dialer.Dialer{
		dialer.SymmetricDirectDialer,
		dialer.FullconeDirectDialer,
	}
	fixedIndex := 1
	g := NewDialerGroup(log, "test-group", dialers, DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: fixedIndex,
	})
	for i := 0; i < 10; i++ {
		d, err := g.Select()
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[fixedIndex] {
			t.Fail()
		}
	}

	fixedIndex = 0
	g.selectionPolicy.FixedIndex = fixedIndex
	for i := 0; i < 10; i++ {
		d, err := g.Select()
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[fixedIndex] {
			t.Fail()
		}
	}
}

func TestDialerGroup_Select_MinLastLatency(t *testing.T) {
	log := logger.NewLogger(2)
	dialers := []*dialer.Dialer{
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
	}
	g := NewDialerGroup(log, "test-group", dialers, DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_MinLastLatency,
	})

	// Test 1000 times.
	for i := 0; i < 1000; i++ {
		var minLatency time.Duration
		jMinLatency := -1
		for j, d := range dialers {
			// Simulate a latency test.
			var (
				latency time.Duration
				alive   bool
			)
			// 20% chance for timeout.
			if fastrand.Intn(5) == 0 {
				// Simulate a timeout test.
				latency = 1000 * time.Millisecond
				alive = false
			} else {
				// Simulate a normal test.
				latency = time.Duration(fastrand.Int63n(int64(1000 * time.Millisecond)))
				alive = true
			}
			d.Latencies10.AppendLatency(latency)
			if jMinLatency == -1 || latency < minLatency {
				jMinLatency = j
				minLatency = latency
			}
			g.AliveDialerSet.SetAlive(d, alive)
		}
		d, err := g.Select()
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[jMinLatency] {
			// Get index of d.
			indexD := -1
			for j := range dialers {
				if d == dialers[j] {
					indexD = j
					break
				}
			}
			t.Errorf("dialers[%v] expected, but dialers[%v] selected", jMinLatency, indexD)
		}
	}
}

func TestDialerGroup_Select_Random(t *testing.T) {
	log := logger.NewLogger(2)
	dialers := []*dialer.Dialer{
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
	}
	g := NewDialerGroup(log, "test-group", dialers, DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Random,
	})
	count := make([]int, len(dialers))
	for i := 0; i < 100; i++ {
		d, err := g.Select()
		if err != nil {
			t.Fatal(err)
		}
		for j, dd := range dialers {
			if d == dd {
				count[j]++
				break
			}
		}
	}
	for i, c := range count {
		if c == 0 {
			t.Fail()
		}
		t.Logf("count[%v]: %v", i, c)
	}
}

func TestDialerGroup_SetAlive(t *testing.T) {
	log := logger.NewLogger(2)
	dialers := []*dialer.Dialer{
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
		dialer.NewDialer(dialer.SymmetricDirect, true, "direct", "direct", ""),
	}
	g := NewDialerGroup(log, "test-group", dialers, DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Random,
	})
	zeroTarget := 3
	g.AliveDialerSet.SetAlive(dialers[zeroTarget], false)
	count := make([]int, len(dialers))
	for i := 0; i < 100; i++ {
		d, err := g.Select()
		if err != nil {
			t.Fatal(err)
		}
		for j, dd := range dialers {
			if d == dd {
				count[j]++
				break
			}
		}
	}
	for i, c := range count {
		if c == 0 && i != zeroTarget {
			t.Fail()
		}
		t.Logf("count[%v]: %v", i, c)
	}
	if count[zeroTarget] != 0 {
		t.Fail()
	}
}
