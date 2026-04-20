/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
)

func TestDnsControllerReportDnsForwardFailure_PenalizesOnlyDnsUdpDomain(t *testing.T) {
	d := newTestProxyEndpointDialer("hysteria2", "proxy.example:443")
	var callbackCalls atomic.Int32
	ctrl := setTestDnsControllerRuntime(&DnsController{}, func(rt *dnsControllerRuntimeState) {
		rt.timeoutExceedCallback = func(dialArg *dialArgument, err error) {
			callbackCalls.Add(1)
		}
	})

	dialArg := &dialArgument{
		l4proto:    consts.L4ProtoStr_UDP,
		ipversion:  consts.IpVersionStr_4,
		bestDialer: d,
	}
	dnsType := &componentdialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		IsDns:           true,
		UdpHealthDomain: componentdialer.UdpHealthDomainDns,
	}
	dataType := &componentdialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		UdpHealthDomain: componentdialer.UdpHealthDomainData,
	}

	for range 3 {
		ctrl.reportDnsForwardFailure(dialArg, io.ErrUnexpectedEOF)
	}

	if got := callbackCalls.Load(); got != 3 {
		t.Fatalf("timeoutExceedCallback calls = %d, want 3", got)
	}
	if d.MustGetAlive(dnsType) {
		t.Fatal("DNS forward failures should mark only the DNS UDP health domain unavailable")
	}
	if !d.MustGetAlive(dataType) {
		t.Fatal("DNS forward failures should not poison the data UDP health domain")
	}
}

func TestUdpSessionLifecycleContext_HandleReplyPromotesAndRevivesDataUdp(t *testing.T) {
	d := newTestProxyEndpointDialer("hysteria2", "proxy.example:443")
	ue := &UdpEndpoint{
		Dialer:              d,
		NatTimeout:          QuicNatTimeout,
		endpointNetworkType: componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4},
		lifecycleProfile:    newDataSessionLifecycleProfile(d),
	}
	dataType := &componentdialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		UdpHealthDomain: componentdialer.UdpHealthDomainData,
	}

	d.ReportUnavailableForced(dataType, io.ErrUnexpectedEOF)
	if d.MustGetAlive(dataType) {
		t.Fatal("expected data UDP domain to start as unavailable")
	}

	lifecycle, ok := newUdpSessionLifecycleContext(ue, consts.IpVersionStr_4)
	if !ok {
		t.Fatal("expected lifecycle context for UDP endpoint")
	}
	now := time.Now().UnixNano()
	lifecycle.handleReply(ue, now)

	if !ue.hasReply.Load() {
		t.Fatal("reply handling should promote the endpoint to established state")
	}
	if ue.expiresAtNano.Load() <= now {
		t.Fatal("reply handling should refresh the endpoint expiry")
	}
	if !d.MustGetAlive(dataType) {
		t.Fatal("reply handling should report data UDP traffic success through the shared lifecycle context")
	}
}
