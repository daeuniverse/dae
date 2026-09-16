/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// Shared control-plane test fixtures recovered from pruned bulk test files
// (Sprint 5 T1). These are referenced by multiple surviving (including
// non-bulk fuzz-corpus and bench) test files, so they are centralized here.
// No build tag (matches original definitions).

// errorDialer is a netproxy.Dialer that always returns a fixed error.
// Recovered from udp_endpoint_pool_test.go.
type errorDialer struct {
	err   error
	calls atomic.Int32
}

func (d *errorDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	d.calls.Add(1)
	return nil, d.err
}

// newTestEndpointDialer builds a componentdialer backed by scriptedDialer.
// Recovered from udp_endpoint_pool_test.go.
func newTestEndpointDialer(conns ...netproxy.Conn) *componentdialer.Dialer {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return componentdialer.NewDialerContext(context.Background(),
		&scriptedDialer{conns: conns},
		&componentdialer.GlobalOption{
			Log:           logger,
			CheckInterval: time.Second,
		},
		componentdialer.InstanceOption{DisableCheck: true},
		&componentdialer.Property{},
	)
}

// newTestEndpointErrorDialer builds a componentdialer backed by errorDialer.
// Recovered from udp_endpoint_pool_test.go.
func newTestEndpointErrorDialer(protocol, address string, err error) (*componentdialer.Dialer, *errorDialer) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	underlay := &errorDialer{err: err}
	return componentdialer.NewDialerContext(context.Background(),
		underlay,
		&componentdialer.GlobalOption{
			Log:           logger,
			CheckInterval: time.Second,
		},
		componentdialer.InstanceOption{DisableCheck: true},
		&componentdialer.Property{
			Property: D.Property{
				Name:     protocol,
				Address:  address,
				Protocol: protocol,
			},
		},
	), underlay
}

// newTestFixedOutboundGroup builds a DialerGroup with Fixed selection policy.
// Recovered from udp_endpoint_pool_test.go.
func newTestFixedOutboundGroup(dialers ...*componentdialer.Dialer) *ob.DialerGroup {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	annotations := make([]*componentdialer.Annotation, 0, len(dialers))
	for range dialers {
		annotations = append(annotations, &componentdialer.Annotation{})
	}
	return ob.NewDialerGroup(
		&componentdialer.GlobalOption{
			Log:           logger,
			CheckInterval: time.Second,
		},
		"fixed-test",
		dialers,
		annotations,
		ob.DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 0,
		},
		func(bool, *componentdialer.NetworkType, bool) {},
	)
}

// stubDnsForwarder is a minimal DnsForwarder for DNS corpus/fallback tests.
// Recovered from dns_fallback_test.go.
type stubDnsForwarder struct {
	forward func(ctx context.Context, data []byte) (*dnsmessage.Msg, error)
}

func (s *stubDnsForwarder) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	if s.forward == nil {
		return nil, nil
	}
	return s.forward(ctx, data)
}

func (s *stubDnsForwarder) Close() error { return nil }

// newTestDialControlPlane builds a ControlPlane with a single outbound group
// installed at the user-defined slot. Recovered from dial_family_fallback_test.go.
func newTestDialControlPlane(outbound *ob.DialerGroup) *ControlPlane {
	outbounds := make([]*ob.DialerGroup, int(consts.OutboundUserDefinedMin)+1)
	outbounds[consts.OutboundUserDefinedMin] = outbound
	return &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds: outbounds,
		},
		soMarkFromDae: 0x100,
	}
}

// waitForCloseSignal blocks until ch closes or times out. Recovered from
// udp_endpoint_pool_test.go (used by udp_reuse_simulation_test).
func waitForCloseSignal(t *testing.T, ch <-chan struct{}, context string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for close signal: %s", context)
	}
}
