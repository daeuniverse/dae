/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/panjf2000/ants/v2"
)

func registerTestAliveSet(t *testing.T, d *Dialer, networkType *NetworkType) *AliveDialerSet {
	t.Helper()

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
	return aliveSet
}

func TestDialerCheck_UsesDialerContext(t *testing.T) {
	d := newTestDialer(t)
	networkType := newTestNetworkType()
	aliveSet := registerTestAliveSet(t, d, networkType)

	d.cancel()

	ok, err := d.Check(&CheckOption{
		networkType: networkType,
		CheckFunc: func(ctx context.Context, _ *NetworkType) (bool, error) {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			return false, errors.New("dialer context was not propagated")
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Check() error = %v, want %v", err, context.Canceled)
	}
	if ok {
		t.Fatal("unexpected ok=true for canceled dialer")
	}
	if !d.MustGetAlive(networkType) {
		t.Fatal("context cancellation should not mark dialer unavailable")
	}
	if aliveSet.GetRand() == nil {
		t.Fatal("alive dialer set should keep canceled dialer available")
	}
}

func TestSubmitCheckTasks_PoolOverloadSkipsProbe(t *testing.T) {
	d := newTestDialer(t)
	networkType := newTestNetworkType()
	registerTestAliveSet(t, d, networkType)

	workerPool, err := ants.NewPool(1, ants.WithNonblocking(true))
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer workerPool.Release()

	blockWorker := make(chan struct{})
	if err := workerPool.Submit(func() {
		<-blockWorker
	}); err != nil {
		t.Fatalf("initial Submit() error = %v", err)
	}
	defer close(blockWorker)

	var called atomic.Int32
	var wg sync.WaitGroup
	d.submitCheckTasks(workerPool, &wg, []*CheckOption{{
		networkType: networkType,
		CheckFunc: func(context.Context, *NetworkType) (bool, error) {
			called.Add(1)
			return true, nil
		},
	}}, false, nil)

	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("submitCheckTasks should not block on overloaded nonblocking pool")
	}
	if got := called.Load(); got != 0 {
		t.Fatalf("overloaded pool should skip probe, got %d executions", got)
	}
}
