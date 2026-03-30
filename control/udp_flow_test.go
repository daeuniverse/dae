/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"net/netip"
	"testing"
)

func mustParseUdpFlowAddrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	return netip.MustParseAddrPort(s)
}

func TestUdpFlowDecision_HeuristicQuicPortDoesNotForceSymmetricAllocation(t *testing.T) {
	src := mustParseUdpFlowAddrPort(t, "192.0.2.10:40000")
	dst := mustParseUdpFlowAddrPort(t, "198.51.100.20:443")
	decision := UdpFlowDecision{
		Key:              NewUdpFlowKey(src, dst),
		IsLikelyQuicData: true,
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
		Key:              NewUdpFlowKey(src, dst),
		IsLikelyQuicData: true,
	}

	if got := decision.EndpointKeyForDial("example.com"); got != decision.SymmetricNatEndpointKey() {
		t.Fatalf("EndpointKeyForDial(domain) = %v, want symmetric %v", got, decision.SymmetricNatEndpointKey())
	}

	if got := decision.NatTimeoutForDial("example.com"); got != QuicNatTimeout {
		t.Fatalf("NatTimeoutForDial(domain) = %v, want %v", got, QuicNatTimeout)
	}
}
