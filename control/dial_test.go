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
		log:           log,
		outbounds:     []*outbound.DialerGroup{group},
		soMarkFromDae: 1234,
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

func TestRouteDialTcp_ConcurrentCallsAreSafe(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	stub := &instantErrorDialer{}
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

	const goroutines = 100
	const callsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < callsPerGoroutine; j++ {
				_, err := cp.RouteDialTcp(context.Background(), p)
				if err != nil && !errors.Is(err, errTestDialFailure) {
					t.Errorf("unexpected error: %v", err)
				}
			}
		}()
	}

	wg.Wait()

	// Verify all calls reached the dialer
	expectedCalls := int64(goroutines * callsPerGoroutine)
	if got := stub.called.Load(); got != expectedCalls {
		t.Errorf("expected %d dialer calls, got %d", expectedCalls, got)
	}
}
