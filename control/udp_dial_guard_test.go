/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func TestShouldRejectNewUdpDialSelection(t *testing.T) {
	d := newTestEndpointDialer()
	udp6 := &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStr_6,
		IsDns:     false,
	}
	tcp6 := &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_6,
		IsDns:     false,
	}

	if shouldRejectNewUdpDialSelection(&proxyDialResult{
		Dialer:                  d,
		SelectionNetworkTypeObj: udp6,
	}) {
		t.Fatal("expected healthy UDP dialer selection to be admitted")
	}

	d.ReportUnavailableForced(udp6, nil)

	if !shouldRejectNewUdpDialSelection(&proxyDialResult{
		Dialer:                  d,
		SelectionNetworkTypeObj: udp6,
	}) {
		t.Fatal("expected unhealthy UDP dialer selection to be rejected")
	}

	if shouldRejectNewUdpDialSelection(&proxyDialResult{
		Dialer:                  d,
		SelectionNetworkTypeObj: tcp6,
	}) {
		t.Fatal("expected TCP selection to ignore UDP dial guard")
	}
}

func TestShouldRejectNewUdpDialSelection_FixedOutboundIgnoresHealth(t *testing.T) {
	d := newTestEndpointDialer()
	udp6 := &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStr_6,
		IsDns:     false,
	}
	outbound := newTestFixedOutboundGroup(d)

	d.ReportUnavailableForced(udp6, nil)

	if shouldRejectNewUdpDialSelection(&proxyDialResult{
		Outbound:                outbound,
		Dialer:                  d,
		SelectionNetworkTypeObj: udp6,
	}) {
		t.Fatal("expected fixed outbound UDP selection to ignore health rejection")
	}
}

func TestShouldRejectNewUdpDialSelection_SingleDialerFallbackStillRejects(t *testing.T) {
	d := newTestEndpointDialer()
	udp6 := &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStr_6,
		IsDns:     false,
	}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	outbound := ob.NewDialerGroup(
		&componentdialer.GlobalOption{
			Log:           logger,
			CheckInterval: time.Second,
		},
		"single-random",
		[]*componentdialer.Dialer{d},
		[]*componentdialer.Annotation{{}},
		ob.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		},
		func(bool, *componentdialer.NetworkType, bool) {},
	)

	d.ReportUnavailableForced(udp6, nil)

	if !shouldRejectNewUdpDialSelection(&proxyDialResult{
		Outbound:                outbound,
		Dialer:                  d,
		SelectionNetworkTypeObj: udp6,
	}) {
		t.Fatal("expected non-fixed single-dialer fallback to be rejected")
	}
}

func TestCheckUdpEndpointHealth_UsesEndpointSelectionNetworkType(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	d := newTestEndpointDialer()
	udp6 := &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStr_6,
		IsDns:     false,
	}
	d.ReportUnavailableForced(udp6, nil)

	key := UdpEndpointKey{
		Src: netip.MustParseAddrPort("192.0.2.10:12345"),
		Dst: netip.MustParseAddrPort("198.51.100.20:443"),
	}
	ue := &UdpEndpoint{
		Dialer:              d,
		lAddr:               key.Src,
		log:                 logger,
		poolRef:             DefaultUdpEndpointPool,
		poolKey:             key,
		endpointNetworkType: *udp6,
	}

	shard := DefaultUdpEndpointPool.shardFor(key)
	shard.mu.Lock()
	shard.pool[key] = ue
	shard.mu.Unlock()

	c := &ControlPlane{log: logger}
	if c.checkUdpEndpointHealth(ue, key, false) {
		t.Fatal("expected endpoint health check to reject unavailable endpoint network type")
	}
	if _, ok := DefaultUdpEndpointPool.Get(key); ok {
		t.Fatal("expected rejected endpoint to be removed from pool")
	}
}
