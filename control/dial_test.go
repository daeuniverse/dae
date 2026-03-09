/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	odialer "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

var errTestDialFailure = errors.New("test dial failure")

type ctxCaptureDialer struct {
	ctx context.Context
}

func (d *ctxCaptureDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	d.ctx = ctx
	return nil, errTestDialFailure
}

type blockingDialer struct {
	mu        sync.RWMutex
	active    atomic.Int32
	maxActive atomic.Int32
	entered   chan struct{}
	release   <-chan struct{}
}

func (d *blockingDialer) setRelease(ch <-chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.release = ch
}

func (d *blockingDialer) currentRelease() <-chan struct{} {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.release
}

func (d *blockingDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	current := d.active.Add(1)
	for {
		seen := d.maxActive.Load()
		if current <= seen || d.maxActive.CompareAndSwap(seen, current) {
			break
		}
	}
	select {
	case d.entered <- struct{}{}:
	default:
	}
	defer d.active.Add(-1)
	release := d.currentRelease()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-release:
		return nil, errTestDialFailure
	}
}

type instantErrorDialer struct {
	called atomic.Int64
}

func (d *instantErrorDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	d.called.Add(1)
	return nil, errTestDialFailure
}

func newFixedSingleDialerControlPlaneForTest(t testing.TB, log *logrus.Logger, underlying netproxy.Dialer, limit int) (*ControlPlane, *dialer.Dialer) {
	t.Helper()
	gOption := &dialer.GlobalOption{Log: log}
	wrapped := dialer.NewDialer(underlying, gOption, dialer.InstanceOption{}, &dialer.Property{
		Property: odialer.Property{Name: "fixed-storm-guard-stub"},
	})
	group := outbound.NewDialerGroup(
		gOption,
		"fixed-proxy",
		[]*dialer.Dialer{wrapped},
		[]*dialer.Annotation{{}},
		outbound.DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 0,
		},
		func(alive bool, networkType *dialer.NetworkType, isInit bool) {},
	)

	cp := &ControlPlane{
		log:                log,
		outbounds:          []*outbound.DialerGroup{group},
		soMarkFromDae:      1234,
		fixedTcpDialGuards: map[*dialer.Dialer]chan struct{}{wrapped: make(chan struct{}, limit)},
	}
	return cp, wrapped
}

func newRouteDialParamForTest() *RouteDialParam {
	return &RouteDialParam{
		Outbound: consts.OutboundDirect,
		Src:      netip.MustParseAddrPort("127.0.0.1:20000"),
		Dest:     netip.MustParseAddrPort("1.1.1.1:443"),
	}
}

func TestRouteDialTcp_NilContextDoesNotPanic(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	stub := &ctxCaptureDialer{}
	gOption := &dialer.GlobalOption{Log: log}
	wrapped := dialer.NewDialer(stub, gOption, dialer.InstanceOption{}, &dialer.Property{
		Property: odialer.Property{Name: "stub"},
	})
	group := outbound.NewDialerGroup(
		gOption,
		"direct",
		[]*dialer.Dialer{wrapped},
		[]*dialer.Annotation{{}},
		outbound.DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 0,
		},
		func(alive bool, networkType *dialer.NetworkType, isInit bool) {},
	)

	cp := &ControlPlane{
		log:           log,
		outbounds:     []*outbound.DialerGroup{group},
		soMarkFromDae: 1234,
	}
	p := &RouteDialParam{
		Outbound: consts.OutboundDirect,
		Src:      netip.MustParseAddrPort("127.0.0.1:20000"),
		Dest:     netip.MustParseAddrPort("1.1.1.1:443"),
	}

	var (
		panicVal any
		err      error
	)
	func() {
		defer func() { panicVal = recover() }()
		_, err = cp.RouteDialTcp(nil, p)
	}()

	if panicVal != nil {
		t.Fatalf("RouteDialTcp should not panic with nil context: %v", panicVal)
	}
	if !errors.Is(err, errTestDialFailure) {
		t.Fatalf("unexpected dial error: %v", err)
	}
	if stub.ctx == nil {
		t.Fatal("dialer should receive a non-nil context")
	}
	if _, ok := stub.ctx.Deadline(); !ok {
		t.Fatal("dialer context should include timeout deadline")
	}
}

func TestRouteDialTcp_FixedSingleDialerConcurrencyGuard(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	release := make(chan struct{})
	stub := &blockingDialer{
		entered: make(chan struct{}, 16),
		release: release,
	}

	const limit = 2
	cp, _ := newFixedSingleDialerControlPlaneForTest(t, log, stub, limit)
	p := newRouteDialParamForTest()

	const total = 6
	results := make(chan error, total)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range total {
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
			t.Fatalf("timed out waiting for admitted dial %d", i)
		}
	}

	for i := 0; i < total-limit; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, ErrFixedTcpDialConcurrencyLimitExceeded) {
				t.Fatalf("expected concurrency guard error, got %v", err)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatal("excess dials should fail fast when guard is saturated")
		}
	}

	if got := stub.maxActive.Load(); got != limit {
		t.Fatalf("expected max active dials %d, got %d", limit, got)
	}

	close(release)
	for i := 0; i < limit; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, errTestDialFailure) {
				t.Fatalf("expected underlying dial failure after release, got %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for admitted dial result %d", i)
		}
	}

	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("unexpected extra result: %v", err)
		}
	}
}
