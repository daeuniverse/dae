/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net/netip"
	"reflect"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
)

func dialerSignalChannelLen(t *testing.T, d *componentdialer.Dialer, field string) int {
	t.Helper()
	v := reflect.ValueOf(d).Elem().FieldByName(field)
	if !v.IsValid() {
		t.Fatalf("dialer field %q not found", field)
	}
	if v.Kind() != reflect.Chan {
		t.Fatalf("dialer field %q kind = %v, want chan", field, v.Kind())
	}
	return v.Len()
}

func TestRouteDial_ProxyDialFailureNotifiesTcpHealthCheck(t *testing.T) {
	d, _ := newTestEndpointErrorDialer("hysteria2", "proxy.example:443", io.ErrUnexpectedEOF)
	cp := newTestDialControlPlane(newTestFixedOutboundGroup(d))

	_, _, err := cp.routeDial(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Src:      netip.MustParseAddrPort("192.0.2.10:34567"),
		Dest:     netip.MustParseAddrPort("198.51.100.10:443"),
		Network:  "tcp",
	})
	if err == nil {
		t.Fatal("routeDial() error = nil, want failure")
	}
	if got := dialerSignalChannelLen(t, d, "checkTcpCh"); got != 1 {
		t.Fatalf("checkTcpCh len = %d, want 1", got)
	}
	if got := dialerSignalChannelLen(t, d, "checkDnsUdpCh"); got != 0 {
		t.Fatalf("checkDnsUdpCh len = %d, want 0", got)
	}
}

func TestRouteDial_DirectDialFailureDoesNotNotifyHealthCheck(t *testing.T) {
	d := newTestEndpointDialer()
	cp := newTestDialControlPlane(newTestFixedOutboundGroup(d))

	_, _, err := cp.routeDial(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Src:      netip.MustParseAddrPort("192.0.2.20:45678"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "tcp",
	})
	if err == nil {
		t.Fatal("routeDial() error = nil, want failure")
	}
	if got := dialerSignalChannelLen(t, d, "checkTcpCh"); got != 0 {
		t.Fatalf("checkTcpCh len = %d, want 0", got)
	}
	if got := dialerSignalChannelLen(t, d, "checkDnsUdpCh"); got != 0 {
		t.Fatalf("checkDnsUdpCh len = %d, want 0", got)
	}
}

func TestDnsControllerReportDnsForwardFailure_NotifiesDnsUdpHealthCheck(t *testing.T) {
	d := newTestProxyEndpointDialer("hysteria2", "proxy.example:443")
	ctrl := &DnsController{}
	dialArg := &dialArgument{
		l4proto:    consts.L4ProtoStr_UDP,
		ipversion:  consts.IpVersionStr_4,
		bestDialer: d,
	}

	ctrl.reportDnsForwardFailure(dialArg, io.ErrUnexpectedEOF)

	if got := dialerSignalChannelLen(t, d, "checkDnsUdpCh"); got != 1 {
		t.Fatalf("checkDnsUdpCh len = %d, want 1", got)
	}
	if got := dialerSignalChannelLen(t, d, "checkTcpCh"); got != 0 {
		t.Fatalf("checkTcpCh len = %d, want 0", got)
	}
}
