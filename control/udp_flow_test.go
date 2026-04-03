/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func mustParseUdpFlowAddrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	return netip.MustParseAddrPort(s)
}

func TestUdpFlowDecision_SniffEligiblePortDoesNotForceSymmetricAllocation(t *testing.T) {
	src := mustParseUdpFlowAddrPort(t, "192.0.2.10:40000")
	dst := mustParseUdpFlowAddrPort(t, "198.51.100.20:443")
	decision := UdpFlowDecision{
		Key:            NewUdpFlowKey(src, dst),
		AllowsSniffing: true,
	}

	if got := decision.EndpointKeyForInitialLookup(); got != decision.SymmetricNatEndpointKey() {
		t.Fatalf("EndpointKeyForInitialLookup() = %v, want symmetric %v", got, decision.SymmetricNatEndpointKey())
	}

	fallbackKey, ok := decision.InitialLookupFallbackKey()
	if !ok {
		t.Fatal("InitialLookupFallbackKey() = no fallback, want src-only fallback")
	}
	if fallbackKey != decision.FullConeNatEndpointKey() {
		t.Fatalf("InitialLookupFallbackKey() = %v, want full-cone %v", fallbackKey, decision.FullConeNatEndpointKey())
	}

	if got := decision.EndpointKeyForDial(""); got != decision.FullConeNatEndpointKey() {
		t.Fatalf("EndpointKeyForDial(\"\") = %v, want full-cone %v", got, decision.FullConeNatEndpointKey())
	}

	if got := decision.NatTimeoutForDial(""); got != DefaultNatTimeout {
		t.Fatalf("NatTimeoutForDial(\"\") = %v, want %v", got, DefaultNatTimeout)
	}

	if got := decision.CachedRoutingEndpointKey(); got != decision.FullConeNatEndpointKey() {
		t.Fatalf("CachedRoutingEndpointKey() = %v, want full-cone %v", got, decision.FullConeNatEndpointKey())
	}

	cacheFallback, ok := decision.CachedRoutingFallbackKey()
	if !ok {
		t.Fatal("CachedRoutingFallbackKey() = no fallback, want symmetric fallback")
	}
	if cacheFallback != decision.SymmetricNatEndpointKey() {
		t.Fatalf("CachedRoutingFallbackKey() = %v, want symmetric %v", cacheFallback, decision.SymmetricNatEndpointKey())
	}
}

func TestUdpFlowDecision_ConfirmedQuicKeepsSymmetricAllocation(t *testing.T) {
	src := mustParseUdpFlowAddrPort(t, "192.0.2.10:40000")
	dst := mustParseUdpFlowAddrPort(t, "198.51.100.20:443")
	decision := UdpFlowDecision{
		Key:           NewUdpFlowKey(src, dst),
		IsQuicInitial: true,
	}

	if !decision.HasConfirmedQuicState() {
		t.Fatal("HasConfirmedQuicState() = false, want true")
	}

	if got := decision.EndpointKeyForInitialLookup(); got != decision.SymmetricNatEndpointKey() {
		t.Fatalf("EndpointKeyForInitialLookup() = %v, want symmetric %v", got, decision.SymmetricNatEndpointKey())
	}

	if _, ok := decision.InitialLookupFallbackKey(); ok {
		t.Fatal("InitialLookupFallbackKey() = fallback, want no fallback for confirmed QUIC")
	}

	if got := decision.EndpointKeyForDial(""); got != decision.SymmetricNatEndpointKey() {
		t.Fatalf("EndpointKeyForDial(\"\") = %v, want symmetric %v", got, decision.SymmetricNatEndpointKey())
	}

	if got := decision.NatTimeoutForDial(""); got != QuicNatTimeout {
		t.Fatalf("NatTimeoutForDial(\"\") = %v, want %v", got, QuicNatTimeout)
	}

	if got := decision.CachedRoutingEndpointKey(); got != decision.SymmetricNatEndpointKey() {
		t.Fatalf("CachedRoutingEndpointKey() = %v, want symmetric %v", got, decision.SymmetricNatEndpointKey())
	}

	if _, ok := decision.CachedRoutingFallbackKey(); ok {
		t.Fatal("CachedRoutingFallbackKey() = fallback, want no fallback for confirmed QUIC")
	}
}

func TestUdpFlowDecision_DomainPromotesSymmetricDialPlan(t *testing.T) {
	src := mustParseUdpFlowAddrPort(t, "192.0.2.10:40000")
	dst := mustParseUdpFlowAddrPort(t, "198.51.100.20:443")
	decision := UdpFlowDecision{
		Key:            NewUdpFlowKey(src, dst),
		AllowsSniffing: true,
	}

	if got := decision.EndpointKeyForDial("example.com"); got != decision.SymmetricNatEndpointKey() {
		t.Fatalf("EndpointKeyForDial(domain) = %v, want symmetric %v", got, decision.SymmetricNatEndpointKey())
	}

	if got := decision.NatTimeoutForDial("example.com"); got != QuicNatTimeout {
		t.Fatalf("NatTimeoutForDial(domain) = %v, want %v", got, QuicNatTimeout)
	}
}

func TestClassifyUdpFlow_Only443And8443EnableUdpSniffing(t *testing.T) {
	src := mustParseUdpFlowAddrPort(t, "192.0.2.10:40000")
	initialLikePayload := makeLikelyQuicInitialPayload(0x61)

	httpsDecision := ClassifyUdpFlow(src, mustParseUdpFlowAddrPort(t, "198.51.100.20:443"), initialLikePayload)
	if !httpsDecision.IsQuicInitial {
		t.Fatal("expected udp/443 Initial-shaped payload to stay sniff-eligible")
	}
	if !httpsDecision.AllowsSniffing {
		t.Fatal("expected udp/443 flow to remain in the sniff allowlist")
	}

	doqDecision := ClassifyUdpFlow(src, mustParseUdpFlowAddrPort(t, "198.51.100.20:8443"), initialLikePayload)
	if !doqDecision.IsQuicInitial {
		t.Fatal("expected udp/8443 Initial-shaped payload to stay sniff-eligible")
	}
	if !doqDecision.AllowsSniffing {
		t.Fatal("expected udp/8443 flow to remain in the sniff allowlist")
	}

	altPortDecision := ClassifyUdpFlow(src, mustParseUdpFlowAddrPort(t, "198.51.100.20:853"), initialLikePayload)
	if altPortDecision.IsQuicInitial {
		t.Fatal("expected udp/853 Initial-shaped payload to bypass sniffing")
	}
	if altPortDecision.AllowsSniffing {
		t.Fatal("expected udp/853 flow to bypass the sniff allowlist")
	}
	if altPortDecision.HasConfirmedQuicState() {
		t.Fatal("expected udp/853 flow to avoid confirmed QUIC state without sniff eligibility")
	}
	if got := altPortDecision.EndpointKeyForInitialLookup(); got != altPortDecision.FullConeNatEndpointKey() {
		t.Fatalf("EndpointKeyForInitialLookup() = %v, want full-cone %v", got, altPortDecision.FullConeNatEndpointKey())
	}
}

func TestUdpEndpointRouteScope_ControlPlaneRoutingSeparatesDscpAndForcesDestinationAffinity(t *testing.T) {
	src := mustParseUdpFlowAddrPort(t, "192.0.2.10:40000")
	dst := mustParseUdpFlowAddrPort(t, "198.51.100.20:40001")
	decision := UdpFlowDecision{
		Key: NewUdpFlowKey(src, dst),
	}
	firstResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundControlPlaneRouting),
		Dscp:     8,
	}
	secondResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundControlPlaneRouting),
		Dscp:     46,
	}

	if !udpRouteScopeNeedsDestinationAffinity(firstResult) {
		t.Fatal("udpRouteScopeNeedsDestinationAffinity() = false, want true for userspace-routed UDP")
	}

	firstScope := newUdpEndpointRouteScope(firstResult)
	secondScope := newUdpEndpointRouteScope(secondResult)
	firstKey := decision.EndpointKeyForInitialLookupWithScope(firstScope, true)
	secondKey := decision.EndpointKeyForInitialLookupWithScope(secondScope, true)

	if firstKey.Dst != dst {
		t.Fatalf("EndpointKeyForInitialLookupWithScope().Dst = %v, want %v", firstKey.Dst, dst)
	}
	if firstKey == secondKey {
		t.Fatalf("EndpointKeyForInitialLookupWithScope() reused key across DSCP values: %v", firstKey)
	}
	if _, ok := decision.InitialLookupFallbackKeyWithScope(firstScope, true); ok {
		t.Fatal("InitialLookupFallbackKeyWithScope() = fallback, want no fallback when destination affinity is forced")
	}
}

func TestUdpEndpointRouteScope_FinalKernelOutboundIgnoresDscp(t *testing.T) {
	first := newUdpEndpointRouteScope(&bpfRoutingResult{
		Outbound: uint8(consts.OutboundDirect),
		Dscp:     8,
	})
	second := newUdpEndpointRouteScope(&bpfRoutingResult{
		Outbound: uint8(consts.OutboundDirect),
		Dscp:     46,
	})

	if first != second {
		t.Fatalf("newUdpEndpointRouteScope() = %v and %v, want identical scope for final kernel-routed outbounds", first, second)
	}
}
