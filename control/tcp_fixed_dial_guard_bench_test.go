/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func BenchmarkRouteDialTcp_FixedSingleDialerGuardAdmitted_Parallel(b *testing.B) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	stub := &instantErrorDialer{}
	cp, _ := newFixedSingleDialerControlPlaneForTest(b, log, stub, 65536)
	p := newRouteDialParamForTest()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := cp.RouteDialTcp(context.Background(), p)
			if !errors.Is(err, errTestDialFailure) {
				b.Fatalf("expected underlying dial failure, got %v", err)
			}
		}
	})
}

func BenchmarkRouteDialTcp_FixedSingleDialerGuardRejected_Parallel(b *testing.B) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	stub := &instantErrorDialer{}
	cp, wrapped := newFixedSingleDialerControlPlaneForTest(b, log, stub, 1)
	p := newRouteDialParamForTest()
	guard := cp.fixedTcpDialGuards[wrapped]
	guard <- struct{}{}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := cp.RouteDialTcp(context.Background(), p)
			if !errors.Is(err, ErrFixedTcpDialConcurrencyLimitExceeded) {
				b.Fatalf("expected concurrency guard rejection, got %v", err)
			}
		}
	})
	b.StopTimer()

	if called := stub.called.Load(); called != 0 {
		b.Fatalf("rejected path should not reach underlying dialer, got %d calls", called)
	}
}

func BenchmarkAcquireFixedTcpDialSlot(b *testing.B) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	stub := &instantErrorDialer{}
	cp, wrapped := newFixedSingleDialerControlPlaneForTest(b, log, stub, 1024)
	res := &proxyDialResult{
		Outbound: cp.outbounds[0],
		Dialer:   wrapped,
		Network:  "tcp",
	}
	p := &proxyDialParam{Network: "tcp"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		release, err := cp.acquireFixedTcpDialSlot(context.Background(), p, res)
		if err != nil {
			b.Fatalf("unexpected acquire error: %v", err)
		}
		release()
	}
}

var _ *dialer.Dialer