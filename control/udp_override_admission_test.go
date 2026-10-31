/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

func newAdmissionTestGroup(t *testing.T) (*ob.DialerGroup, []*dialer.Dialer) {
	t.Helper()
	log := logrus.New()
	option := &dialer.GlobalOption{
		Log:           log,
		CheckInterval: 15 * time.Second,
	}
	dialers := []*dialer.Dialer{
		dialer.NewDialerContext(context.Background(), noopAdmissionDialer{}, option,
			dialer.InstanceOption{DisableCheck: true}, &dialer.Property{}),
		dialer.NewDialerContext(context.Background(), noopAdmissionDialer{}, option,
			dialer.InstanceOption{DisableCheck: true}, &dialer.Property{}),
	}
	group := ob.NewDialerGroup(option, "admission", dialers, []*dialer.Annotation{{}, {}},
		ob.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Random},
		func(bool, *dialer.NetworkType, bool) {})
	t.Cleanup(func() { _ = group.Close() })
	return group, dialers
}

type noopAdmissionDialer struct{}

func (noopAdmissionDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	return nil, errors.New("not implemented")
}

var dataUdp4 = &dialer.NetworkType{
	L4Proto:         consts.L4ProtoStr_UDP,
	IpVersion:       consts.IpVersionStr_4,
	UdpHealthDomain: dialer.UdpHealthDomainData,
}

// A pinned member is an explicit user choice: admission must not drop the
// datagram just because the data-UDP probe domain is dead, otherwise the pin
// would black-hole UDP until the next reload.
func TestShouldRejectNewUdpDialSelectionHonorsPin(t *testing.T) {
	group, dialers := newAdmissionTestGroup(t)
	dialers[0].ReportUnavailableForced(dataUdp4, errors.New("udp down"))

	result := &proxyDialResult{
		Outbound:                group,
		Dialer:                  dialers[0],
		SelectionNetworkTypeObj: dataUdp4,
		AdmissionNetworkTypeObj: dataUdp4,
	}

	if !shouldRejectNewUdpDialSelection(result) {
		t.Fatal("an unhealthy automatic selection must be rejected")
	}

	if _, err := group.SetOverride(ob.SelectionNetworkUDP, 0); err != nil {
		t.Fatal(err)
	}
	if shouldRejectNewUdpDialSelection(result) {
		t.Fatal("a pinned UDP member must not be rejected by probe health")
	}

	if _, err := group.ClearOverride(ob.SelectionNetworkUDP); err != nil {
		t.Fatal(err)
	}
	if !shouldRejectNewUdpDialSelection(result) {
		t.Fatal("clearing the pin must restore health-gated admission")
	}
}
