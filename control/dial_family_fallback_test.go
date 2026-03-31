/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func newTestSingleRandomOutboundGroup(dialers ...*componentdialer.Dialer) *ob.DialerGroup {
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
		"single-random",
		dialers,
		annotations,
		ob.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		},
		func(bool, *componentdialer.NetworkType, bool) {},
	)
}

func newTestDialControlPlane(outbound *ob.DialerGroup) *ControlPlane {
	outbounds := make([]*ob.DialerGroup, int(consts.OutboundUserDefinedMin)+1)
	outbounds[consts.OutboundUserDefinedMin] = outbound
	return &ControlPlane{
		outbounds:     outbounds,
		soMarkFromDae: 0x100,
	}
}

func TestChooseProxyDialer_FixedOutboundFallsBackToAlternateFamilyOnSameDialer(t *testing.T) {
	d := newTestEndpointDialer()
	udp6 := &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStr_6,
		IsDns:     false,
	}
	d.ReportUnavailableForced(udp6, nil)

	cp := newTestDialControlPlane(newTestFixedOutboundGroup(d))
	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Src:      netip.MustParseAddrPort("[2001:db8::10]:12345"),
		Dest:     netip.MustParseAddrPort("[2606:4700:4700::1111]:53"),
		Network:  "udp",
	})
	if err != nil {
		t.Fatalf("chooseProxyDialer() error = %v", err)
	}
	if got := res.SelectionNetworkTypeObj.IpVersion; got != consts.IpVersionStr_4 {
		t.Fatalf("selection ip version = %v, want %v", got, consts.IpVersionStr_4)
	}
}

func TestChooseProxyDialer_SingleDialerGroupFallsBackToAlternateFamilyOnSameDialer(t *testing.T) {
	d := newTestEndpointDialer()
	udp6 := &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStr_6,
		IsDns:     false,
	}
	d.ReportUnavailableForced(udp6, nil)

	cp := newTestDialControlPlane(newTestSingleRandomOutboundGroup(d))
	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Src:      netip.MustParseAddrPort("[2001:db8::10]:12345"),
		Dest:     netip.MustParseAddrPort("[2606:4700:4700::1111]:53"),
		Network:  "udp",
	})
	if err != nil {
		t.Fatalf("chooseProxyDialer() error = %v", err)
	}
	if got := res.SelectionNetworkTypeObj.IpVersion; got != consts.IpVersionStr_4 {
		t.Fatalf("selection ip version = %v, want %v", got, consts.IpVersionStr_4)
	}
}
