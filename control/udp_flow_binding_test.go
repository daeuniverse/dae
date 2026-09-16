/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
)

func TestUdpFlowBindingKeepsRouteAndEgressSeparate(t *testing.T) {
	program, err := routing.NewNormalizedProgram(nil, config.FunctionOrString("direct"))
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}
	identity, err := routing.NewPolicyIdentity(9, program)
	if err != nil {
		t.Fatalf("NewPolicyIdentity() error = %v", err)
	}
	networkType := dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStr_4,
	}
	option := &DialOption{
		Target:        "198.51.100.10:443",
		Network:       "udp+4",
		NetworkType:   &networkType,
		SniffedDomain: "example.com",
		IsDialIp:      true,
	}
	binding := newUdpFlowBinding(identity.Epoch(), 7, 42, true, option)

	if binding.Route.PolicyEpoch != identity.Epoch() || binding.Route.Outbound != 7 || binding.Route.Mark != 42 || !binding.Route.Must {
		t.Fatalf("route binding = %+v", binding.Route)
	}
	if binding.Egress.Target != option.Target || binding.Egress.Network != option.Network || binding.Egress.NetworkType != networkType || binding.Egress.SniffedDomain != option.SniffedDomain || binding.Egress.IsDialIp != option.IsDialIp {
		t.Fatalf("egress binding = %+v", binding.Egress)
	}

	endpoint := &UdpEndpoint{
		Dialer:              binding.Egress.Dialer,
		Outbound:            binding.Egress.Outbound,
		DialTarget:          binding.Egress.Target,
		endpointNetworkType: binding.Egress.NetworkType,
		SniffedDomain:       binding.Egress.SniffedDomain,
	}
	endpoint.setFlowBinding(binding)
	if got := endpoint.FlowBinding(); got != binding {
		t.Fatalf("FlowBinding() = %+v, want %+v", got, binding)
	}
}

func TestUdpEndpointPoolPreservesOriginalFlowBindingOnReuse(t *testing.T) {
	pool := NewUdpEndpointPool()
	t.Cleanup(pool.Close)
	firstTracker := newControlPlaneDrainTracker()
	secondTracker := newControlPlaneDrainTracker()

	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d := newTestEndpointDialer(conn)
	t.Cleanup(func() { _ = d.Close() })

	key := UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.10:40000")}
	firstBinding := UdpFlowBinding{
		Route: UdpRouteBinding{
			PolicyEpoch: 1,
			Outbound:    consts.OutboundUserDefinedMin,
			Mark:        11,
		},
		Egress: UdpEgressBinding{
			Dialer:  d,
			Target:  "198.51.100.1:443",
			Network: "udp+4",
			// FlowBinding() reports the endpoint's normalized network type,
			// so the expectation mirrors what pool creation derives from the
			// flow key (UDP over IPv4).
			NetworkType: dialer.NetworkType{
				L4Proto:         consts.L4ProtoStr_UDP,
				IpVersion:       consts.IpVersionStr_4,
				UdpHealthDomain: dialer.UdpHealthDomainData,
			},
		},
	}
	firstOptions := &UdpEndpointOptions{
		Handler:      func(*UdpEndpoint, []byte, netip.AddrPort) error { return nil },
		DrainTracker: firstTracker,
		GetDialOption: func(context.Context) (*DialOption, error) {
			return &DialOption{
				Dialer:  d,
				Network: "udp+4",
				Target:  "198.51.100.1:443",
				Binding: firstBinding,
			}, nil
		},
	}

	first, isNew, err := pool.GetOrCreate(key, firstOptions)
	if err != nil || !isNew {
		t.Fatalf("first GetOrCreate() = (%v, %v, %v), want new endpoint", first, isNew, err)
	}

	secondBinding := firstBinding
	secondBinding.Route.PolicyEpoch = 2
	secondBinding.Route.Mark = 22
	secondBinding.Egress.Target = "203.0.113.2:443"
	secondDialCalled := false
	secondOptions := &UdpEndpointOptions{
		Handler:      func(*UdpEndpoint, []byte, netip.AddrPort) error { return nil },
		DrainTracker: secondTracker,
		GetDialOption: func(context.Context) (*DialOption, error) {
			secondDialCalled = true
			return &DialOption{Binding: secondBinding}, nil
		},
	}

	second, isNew, err := pool.GetOrCreate(key, secondOptions)
	if err != nil || isNew {
		t.Fatalf("second GetOrCreate() = (%v, %v, %v), want existing endpoint", second, isNew, err)
	}
	if second != first {
		t.Fatal("reused endpoint differs from original endpoint")
	}
	if secondDialCalled {
		t.Fatal("GetDialOption ran while reusing an existing endpoint")
	}
	if got := second.FlowBinding(); got != firstBinding {
		t.Fatalf("reused binding = %+v, want original %+v", got, firstBinding)
	}
	if got := firstTracker.Count(); got != 1 {
		t.Fatalf("original generation active endpoint count = %d, want 1", got)
	}
	if got := secondTracker.Count(); got != 0 {
		t.Fatalf("successor generation active endpoint count = %d, want 0", got)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close reused endpoint: %v", err)
	}
	if got := firstTracker.Count(); got != 0 {
		t.Fatalf("closed endpoint left original generation count = %d, want 0", got)
	}
}

func TestUdpEndpointPoolAdoptUDPSetsFlowBindingOnce(t *testing.T) {
	pool := NewUdpEndpointPool()
	t.Cleanup(pool.Close)

	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d := newTestEndpointDialer(conn)
	t.Cleanup(func() { _ = d.Close() })
	outbound := newTestFixedOutboundGroup(d)
	manager := NewSessionManager(context.Background())
	t.Cleanup(func() { _ = manager.Close() })

	key := UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.10:40001")}
	networkType := dialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		UdpHealthDomain: dialer.UdpHealthDomainData,
	}
	binding := UdpFlowBinding{
		Route: UdpRouteBinding{
			PolicyEpoch: 3,
			Outbound:    consts.OutboundUserDefinedMin,
			Mark:        33,
			Must:        true,
		},
		Egress: UdpEgressBinding{
			Dialer:      d,
			Outbound:    outbound,
			Target:      "198.51.100.3:443",
			Network:     "udp+4",
			NetworkType: networkType,
		},
	}
	endpoint, isNew, err := pool.GetOrCreate(key, &UdpEndpointOptions{
		Handler:        func(*UdpEndpoint, []byte, netip.AddrPort) error { return nil },
		sessionManager: manager,
		GetDialOption: func(context.Context) (*DialOption, error) {
			return &DialOption{
				Dialer:      d,
				Outbound:    outbound,
				Network:     "udp+4",
				NetworkType: &networkType,
				Target:      "198.51.100.3:443",
				Binding:     binding,
			}, nil
		},
	})
	if err != nil || !isNew || endpoint == nil {
		t.Fatalf("GetOrCreate() = (%v, %v, %v), want new endpoint", endpoint, isNew, err)
	}
	got := endpoint.FlowBinding()
	if got.Route != binding.Route {
		t.Fatalf("adopted route = %+v, want %+v", got.Route, binding.Route)
	}
	if got.Egress.Outbound != outbound || got.Egress.Dialer != d || got.Egress.Target != binding.Egress.Target {
		t.Fatalf("adopted egress = %+v, want outbound %p dialer %p target %q", got.Egress, outbound, d, binding.Egress.Target)
	}
	if endpoint.sessionRuntime == nil {
		t.Fatal("adoptUDP did not attach a session runtime")
	}
}
