/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
)

func TestNewDnsLifecycleProfile_ProxyBackedUsesShortIdleAndTimeoutDiscard(t *testing.T) {
	profile := newDnsLifecycleProfile(newTestProxyEndpointDialer("hysteria2", "proxy.example:443"))
	if profile.Kind != UdpLifecycleKindDnsTransactional {
		t.Fatalf("Kind = %v, want %v", profile.Kind, UdpLifecycleKindDnsTransactional)
	}
	if profile.HealthDomain != componentdialer.UdpHealthDomainDns {
		t.Fatalf("HealthDomain = %v, want %v", profile.HealthDomain, componentdialer.UdpHealthDomainDns)
	}
	if !profile.DiscardPooledConnOnTimeout {
		t.Fatal("proxy-backed DNS profile should discard pooled conn on timeout")
	}
	if profile.PooledConnIdleTTL != dnsUdpProxyPoolMaxIdleTime {
		t.Fatalf("PooledConnIdleTTL = %v, want %v", profile.PooledConnIdleTTL, dnsUdpProxyPoolMaxIdleTime)
	}
}

func TestNewDataSessionLifecycleProfile_ProxyBackedRetiresOnNormalClose(t *testing.T) {
	profile := newDataSessionLifecycleProfile(newTestProxyEndpointDialer("hysteria2", "proxy.example:443"))
	if profile.Kind != UdpLifecycleKindDataSession {
		t.Fatalf("Kind = %v, want %v", profile.Kind, UdpLifecycleKindDataSession)
	}
	if profile.HealthDomain != componentdialer.UdpHealthDomainData {
		t.Fatalf("HealthDomain = %v, want %v", profile.HealthDomain, componentdialer.UdpHealthDomainData)
	}
	if !profile.StickyAfterReply || !profile.PromoteOnReply {
		t.Fatal("data session profile should keep established UDP flows sticky")
	}
	if !profile.RetireOnNormalClose {
		t.Fatal("proxy-backed data session should retire on normal close")
	}
}
