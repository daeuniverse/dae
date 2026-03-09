/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestRouteDialTcp_FixedSingleDialerBurstStress(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	const (
		limit = 4
		burst = 32
		waves = 8
	)

	stub := &blockingDialer{
		entered: make(chan struct{}, burst*waves),
		release: nil,
	}
	cp, _ := newFixedSingleDialerControlPlaneForTest(t, log, stub, limit)
	p := newRouteDialParamForTest()

	for wave := 0; wave < waves; wave++ {
		release := make(chan struct{})
		stub.setRelease(release)

		results := make(chan error, burst)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range burst {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := cp.RouteDialTcp(context.Background(), p)
				results <- err
			}()
		}
		close(start)

		for i := 0; i < limit; i++ {
			select {
			case <-stub.entered:
			case <-time.After(2 * time.Second):
				t.Fatalf("wave %d: timed out waiting for admitted dial %d", wave, i)
			}
		}

		fastRejected := 0
		for i := 0; i < burst-limit; i++ {
			select {
			case err := <-results:
				if !errors.Is(err, ErrFixedTcpDialConcurrencyLimitExceeded) {
					t.Fatalf("wave %d: expected fast rejection, got %v", wave, err)
				}
				fastRejected++
			case <-time.After(500 * time.Millisecond):
				t.Fatalf("wave %d: excess dials should fail fast", wave)
			}
		}

		close(release)
		allowedDone := 0
		for i := 0; i < limit; i++ {
			select {
			case err := <-results:
				if !errors.Is(err, errTestDialFailure) {
					t.Fatalf("wave %d: expected underlying dial failure after release, got %v", wave, err)
				}
				allowedDone++
			case <-time.After(2 * time.Second):
				t.Fatalf("wave %d: timed out waiting for admitted dial completion %d", wave, i)
			}
		}

		wg.Wait()
		close(results)
		for err := range results {
			if err != nil {
				t.Fatalf("wave %d: unexpected extra error result: %v", wave, err)
			}
		}

		if fastRejected != burst-limit {
			t.Fatalf("wave %d: expected %d fast rejections, got %d", wave, burst-limit, fastRejected)
		}
		if allowedDone != limit {
			t.Fatalf("wave %d: expected %d admitted completions, got %d", wave, limit, allowedDone)
		}
	}

	if got := stub.maxActive.Load(); got != limit {
		t.Fatalf("expected global max active dials %d, got %d", limit, got)
	}
	if got := len(cp.fixedTcpDialGuards); got != 1 {
		t.Fatalf("expected exactly one fixed dial guard, got %d", got)
	}
}