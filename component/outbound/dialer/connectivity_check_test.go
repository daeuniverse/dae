/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/sirupsen/logrus"
)

func newTestDialer(t *testing.T) *Dialer {
	return newNamedTestDialer(t, "test-dialer")
}

func newNamedTestDialer(t *testing.T, name string) *Dialer {
	t.Helper()

	log := logrus.New()
	log.SetOutput(io.Discard)

	d := NewDialer(
		direct.SymmetricDirect,
		&GlobalOption{
			Log:            log,
			CheckInterval:  time.Minute,
			CheckTolerance: 0,
		},
		InstanceOption{},
		&Property{
			Property: D.Property{Name: name},
		},
	)
	t.Cleanup(func() {
		_ = d.Close()
	})
	return d
}

func newTestNetworkType() *NetworkType {
	return &NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
		IsDns:     true,
	}
}

func TestDialerCheck_SkipDoesNotCascadeToUnavailable(t *testing.T) {
	d := newTestDialer(t)
	networkType := newTestNetworkType()

	aliveSet := NewAliveDialerSet(
		d.Log,
		"test-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_Random,
		[]*Dialer{d},
		[]*Annotation{{}},
		func(bool) {},
		true,
	)
	d.RegisterAliveDialerSet(aliveSet)
	t.Cleanup(func() {
		d.UnregisterAliveDialerSet(aliveSet)
	})

	checkOpt := &CheckOption{
		networkType: networkType,
		CheckFunc: func(context.Context, *NetworkType) (bool, error) {
			// Simulate "skip check" path used by connectivity check
			// when DNS record is missing for this ip-version.
			return false, nil
		},
	}

	for i := 0; i < 128; i++ {
		ok, err := d.Check(checkOpt)
		if err != nil {
			t.Fatalf("unexpected error at round %d: %v", i, err)
		}
		if ok {
			t.Fatalf("unexpected ok=true at round %d", i)
		}
	}

	if !d.MustGetAlive(networkType) {
		t.Fatal("skip checks must not mark dialer unavailable")
	}
	if aliveSet.GetRand() == nil {
		t.Fatal("alive dialer set should keep dialer alive after repeated skip checks")
	}
	if got := d.MustGetLatencies10(networkType).LastNLatencies.Len(); got != 0 {
		t.Fatalf("skip checks should not append latency samples, got %d", got)
	}
	if _, has := d.MustGetLatencies10(networkType).LastLatency(); has {
		t.Fatal("skip checks should not append timeout latency")
	}
}

func TestDialerCheck_ErrorStillMarksUnavailable(t *testing.T) {
	d := newTestDialer(t)
	networkType := newTestNetworkType()

	aliveSet := NewAliveDialerSet(
		d.Log,
		"test-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_Random,
		[]*Dialer{d},
		[]*Annotation{{}},
		func(bool) {},
		true,
	)
	d.RegisterAliveDialerSet(aliveSet)
	t.Cleanup(func() {
		d.UnregisterAliveDialerSet(aliveSet)
	})

	ok, err := d.Check(&CheckOption{
		networkType: networkType,
		CheckFunc: func(context.Context, *NetworkType) (bool, error) {
			return false, errors.New("simulated health check failure")
		},
	})
	if err == nil {
		t.Fatal("expected check error")
	}
	if ok {
		t.Fatal("unexpected ok=true")
	}

	if d.MustGetAlive(networkType) {
		t.Fatal("real check failures must still mark dialer unavailable")
	}
	if aliveSet.GetRand() != nil {
		t.Fatal("alive dialer set should remove unavailable dialer")
	}
	last, has := d.MustGetLatencies10(networkType).LastLatency()
	if !has {
		t.Fatal("expected timeout latency to be appended for failures")
	}
	if last != Timeout {
		t.Fatalf("expected timeout latency %v, got %v", Timeout, last)
	}
}

func TestDialerCheck_SkipPreservesUnavailableState(t *testing.T) {
	d := newTestDialer(t)
	networkType := newTestNetworkType()

	aliveSet := NewAliveDialerSet(
		d.Log,
		"test-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_Random,
		[]*Dialer{d},
		[]*Annotation{{}},
		func(bool) {},
		true,
	)
	d.RegisterAliveDialerSet(aliveSet)
	t.Cleanup(func() {
		d.UnregisterAliveDialerSet(aliveSet)
	})

	_, err := d.Check(&CheckOption{
		networkType: networkType,
		CheckFunc: func(context.Context, *NetworkType) (bool, error) {
			return false, errors.New("simulated health check failure")
		},
	})
	if err == nil {
		t.Fatal("expected initial failure")
	}

	for i := 0; i < 64; i++ {
		ok, skipErr := d.Check(&CheckOption{
			networkType: networkType,
			CheckFunc: func(context.Context, *NetworkType) (bool, error) {
				return false, nil
			},
		})
		if skipErr != nil || ok {
			t.Fatalf("unexpected skip result at round %d: ok=%v err=%v", i, ok, skipErr)
		}
	}

	if d.MustGetAlive(networkType) {
		t.Fatal("skip checks must preserve existing unavailable state")
	}
	if aliveSet.GetRand() != nil {
		t.Fatal("dialer should remain unavailable after skip checks")
	}
	if got := d.MustGetLatencies10(networkType).LastNLatencies.Len(); got != 1 {
		t.Fatalf("skip checks should not append extra samples after failure, got %d", got)
	}
}

func TestDialerCheck_MixedDialersNoCascadeOnSkip(t *testing.T) {
	networkType := newTestNetworkType()
	d1 := newNamedTestDialer(t, "test-dialer-1")
	d2 := newNamedTestDialer(t, "test-dialer-2")

	aliveSet := NewAliveDialerSet(
		d1.Log,
		"test-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_Random,
		[]*Dialer{d1, d2},
		[]*Annotation{{}, {}},
		func(bool) {},
		true,
	)
	d1.RegisterAliveDialerSet(aliveSet)
	d2.RegisterAliveDialerSet(aliveSet)
	t.Cleanup(func() {
		d1.UnregisterAliveDialerSet(aliveSet)
		d2.UnregisterAliveDialerSet(aliveSet)
	})

	_, err := d1.Check(&CheckOption{
		networkType: networkType,
		CheckFunc: func(context.Context, *NetworkType) (bool, error) {
			return false, errors.New("simulated health check failure")
		},
	})
	if err == nil {
		t.Fatal("expected failure from d1")
	}

	for i := 0; i < 128; i++ {
		ok, skipErr := d2.Check(&CheckOption{
			networkType: networkType,
			CheckFunc: func(context.Context, *NetworkType) (bool, error) {
				return false, nil
			},
		})
		if skipErr != nil || ok {
			t.Fatalf("unexpected skip result at round %d: ok=%v err=%v", i, ok, skipErr)
		}
	}

	if d1.MustGetAlive(networkType) {
		t.Fatal("failed dialer should be unavailable")
	}
	if !d2.MustGetAlive(networkType) {
		t.Fatal("skipped dialer should remain available")
	}
	selected := aliveSet.GetRand()
	if selected == nil {
		t.Fatal("alive set should still have an available dialer")
	}
	if selected != d2 {
		t.Fatalf("expected alive dialer to be d2, got %s", selected.Property().Name)
	}
}
