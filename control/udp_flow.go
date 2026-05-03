/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/sniffing"
)

// UdpFlowKey identifies a UDP flow at ingress.
// We intentionally include destination so ordered processing stays scoped to
// a single flow instead of serializing all traffic sharing the same source port.
type UdpFlowKey struct {
	Src netip.AddrPort
	Dst netip.AddrPort
}

type udpEndpointRouteScope struct {
	Outbound uint8
	Mark     uint32
	Dscp     uint8
	Pname    [16]uint8
	Mac      [6]uint8
}

func NewUdpFlowKey(src, dst netip.AddrPort) UdpFlowKey {
	return UdpFlowKey{Src: src, Dst: dst}
}

func NewUdpSrcOnlyFlowKey(src netip.AddrPort) UdpFlowKey {
	return UdpFlowKey{Src: src}
}

func (k UdpFlowKey) PacketSnifferKey() PacketSnifferKey {
	return PacketSnifferKey{LAddr: k.Src, RAddr: k.Dst}
}

func (k UdpFlowKey) SymmetricNatEndpointKey() UdpEndpointKey {
	return UdpEndpointKey{Src: k.Src, Dst: k.Dst}
}

func (k UdpFlowKey) SymmetricNatEndpointKeyWithScope(scope udpEndpointRouteScope) UdpEndpointKey {
	return UdpEndpointKey{Src: k.Src, Dst: k.Dst, RouteScope: scope}
}

func (k UdpFlowKey) FullConeNatEndpointKey() UdpEndpointKey {
	return UdpEndpointKey{Src: k.Src}
}

func (k UdpFlowKey) FullConeNatEndpointKeyWithScope(scope udpEndpointRouteScope) UdpEndpointKey {
	return UdpEndpointKey{Src: k.Src, RouteScope: scope}
}

func newUdpEndpointRouteScope(result *bpfRoutingResult) udpEndpointRouteScope {
	if result == nil {
		return udpEndpointRouteScope{}
	}
	scope := udpEndpointRouteScope{
		Outbound: result.Outbound,
		Mark:     result.Mark,
	}
	if result.Outbound == uint8(consts.OutboundControlPlaneRouting) {
		scope.Dscp = result.Dscp
		scope.Pname = result.Pname
		scope.Mac = result.Mac
	}
	return scope
}

func udpRouteScopeNeedsDestinationAffinity(result *bpfRoutingResult) bool {
	return result != nil && result.Outbound == uint8(consts.OutboundControlPlaneRouting)
}

// UdpFlowDecision centralizes the cheap ingress classification that is shared
// across scheduling, sniffing, and UDP endpoint selection.
type UdpFlowDecision struct {
	Key               UdpFlowKey
	SnifferKey        PacketSnifferKey
	HasSnifferSession bool
	IsQuicInitial     bool
	AllowsSniffing    bool
}

func udpPortAllowsSniffing(port uint16) bool {
	return port == 443 || port == 8443
}

func udpFlowAllowsSniffing(src, dst netip.AddrPort) bool {
	return udpPortAllowsSniffing(dst.Port()) || udpPortAllowsSniffing(src.Port())
}

func ClassifyUdpFlow(src, dst netip.AddrPort, data []byte) UdpFlowDecision {
	key := NewUdpFlowKey(src, dst)
	sniffEligible := udpFlowAllowsSniffing(src, dst)
	isQuicInitial := sniffEligible && sniffing.IsLikelyQuicInitialPacket(data)
	snifferKey := key.PacketSnifferKey()
	if sniffEligible {
		snifferKey = NewPacketSnifferKey(src, dst, data)
	}

	// Tightened UDP sniffing semantics: only explicit QUIC ports (443, 8443) are allowed to
	// enter the sniffing-related flow model. All other UDP bypasses sniffing
	// entirely, even if the payload happens to resemble a QUIC Initial packet.
	return UdpFlowDecision{
		Key:               key,
		SnifferKey:        snifferKey,
		HasSnifferSession: sniffEligible && DefaultPacketSnifferSessionMgr.HasFlowFamilySession(snifferKey),
		IsQuicInitial:     isQuicInitial,
		AllowsSniffing:    sniffEligible,
	}
}

func (d UdpFlowDecision) PacketSnifferKey() PacketSnifferKey {
	if d.SnifferKey.LAddr.IsValid() || d.SnifferKey.RAddr.IsValid() {
		return d.SnifferKey
	}
	return d.Key.PacketSnifferKey()
}

func (d UdpFlowDecision) SymmetricNatEndpointKey() UdpEndpointKey {
	return d.Key.SymmetricNatEndpointKey()
}

func (d UdpFlowDecision) SymmetricNatEndpointKeyWithScope(scope udpEndpointRouteScope) UdpEndpointKey {
	return d.Key.SymmetricNatEndpointKeyWithScope(scope)
}

func (d UdpFlowDecision) FullConeNatEndpointKey() UdpEndpointKey {
	return d.Key.FullConeNatEndpointKey()
}

func (d UdpFlowDecision) FullConeNatEndpointKeyWithScope(scope udpEndpointRouteScope) UdpEndpointKey {
	return d.Key.FullConeNatEndpointKeyWithScope(scope)
}

// HasConfirmedQuicState returns true only for signals that are strong enough to
// justify allocating per-destination state: a QUIC Initial packet or an active
// sniffer session for the same flow.
func (d UdpFlowDecision) HasConfirmedQuicState() bool {
	return d.IsQuicInitial || d.HasSnifferSession
}

func (d UdpFlowDecision) CachedRoutingEndpointKey() UdpEndpointKey {
	if d.HasConfirmedQuicState() {
		return d.SymmetricNatEndpointKey()
	}
	return d.FullConeNatEndpointKey()
}

// CachedRoutingFallbackKey returns the alternate cache key to probe when the
// primary key misses. This preserves hits for already-established symmetric
// sessions while allowing sniff-eligible UDP traffic to store new cache
// entries under the cheaper src-only key.
func (d UdpFlowDecision) CachedRoutingFallbackKey() (UdpEndpointKey, bool) {
	if d.AllowsSniffing && !d.HasConfirmedQuicState() {
		return d.SymmetricNatEndpointKey(), true
	}
	return UdpEndpointKey{}, false
}

func (d UdpFlowDecision) EndpointKeyForDial(domain string) UdpEndpointKey {
	if domain != "" || d.HasConfirmedQuicState() {
		return d.SymmetricNatEndpointKey()
	}
	return d.FullConeNatEndpointKey()
}

func (d UdpFlowDecision) EndpointKeyForDialWithScope(domain string, scope udpEndpointRouteScope, forceSymmetric bool) UdpEndpointKey {
	if forceSymmetric || domain != "" || d.HasConfirmedQuicState() {
		return d.SymmetricNatEndpointKeyWithScope(scope)
	}
	return d.FullConeNatEndpointKeyWithScope(scope)
}

func (d UdpFlowDecision) NatTimeoutForDial(domain string) time.Duration {
	if domain != "" || d.HasConfirmedQuicState() {
		return QuicNatTimeout
	}
	return DefaultNatTimeout
}

// EndpointKeyForInitialLookup returns the appropriate endpoint pool key for the initial lookup.
// Port-based sniff eligibility is intentionally used here only for reuse of an
// already-established symmetric session. Allocation decisions are deferred
// until after the lookup so sniff-eligible UDP can still fall back to the
// cheaper src-only key on a miss.
func (d UdpFlowDecision) EndpointKeyForInitialLookup() UdpEndpointKey {
	if d.HasConfirmedQuicState() || d.AllowsSniffing {
		return d.SymmetricNatEndpointKey() // {Src, Dst}
	}
	return d.FullConeNatEndpointKey() // {Src, 0}
}

func (d UdpFlowDecision) EndpointKeyForInitialLookupWithScope(scope udpEndpointRouteScope, forceSymmetric bool) UdpEndpointKey {
	if forceSymmetric || d.HasConfirmedQuicState() || d.AllowsSniffing {
		return d.SymmetricNatEndpointKeyWithScope(scope) // {Src, Dst}
	}
	return d.FullConeNatEndpointKeyWithScope(scope) // {Src, 0}
}

// InitialLookupFallbackKey returns the cheaper fallback key used after a miss
// on the sniff-eligible symmetric lookup path. This prevents sniff-eligible UDP
// traffic from permanently allocating per-destination state.
func (d UdpFlowDecision) InitialLookupFallbackKey() (UdpEndpointKey, bool) {
	if d.AllowsSniffing && !d.HasConfirmedQuicState() {
		return d.FullConeNatEndpointKey(), true
	}
	return UdpEndpointKey{}, false
}

func (d UdpFlowDecision) InitialLookupFallbackKeyWithScope(scope udpEndpointRouteScope, forceSymmetric bool) (UdpEndpointKey, bool) {
	if forceSymmetric {
		return UdpEndpointKey{}, false
	}
	if d.AllowsSniffing && !d.HasConfirmedQuicState() {
		return d.FullConeNatEndpointKeyWithScope(scope), true
	}
	return UdpEndpointKey{}, false
}

func (d UdpFlowDecision) EnsureSnifferSession() UdpFlowDecision {
	if d.HasSnifferSession || !d.IsQuicInitial {
		return d
	}
	_, _ = DefaultPacketSnifferSessionMgr.GetOrCreate(d.PacketSnifferKey(), nil)
	d.HasSnifferSession = true
	return d
}

func (d UdpFlowDecision) ShouldAttemptSniff() bool {
	return d.HasSnifferSession || d.IsQuicInitial
}

func (d UdpFlowDecision) ShouldUseOrderedIngress() bool {
	// Preserve ingress order for every session-oriented UDP flow once dae has
	// accepted the packet. Without this, ordinary UDP/game traffic can reach
	// handlePkt and ue.WriteTo through multiple concurrent goroutines, which
	// means same-flow packets are no longer guaranteed to arrive at the outbound
	// in the order they were read from the client socket.
	//
	// Keep a narrow direct-dispatch escape hatch only for request/response and
	// ultra-latency-sensitive protocols where same-flow FIFO is less important
	// than shaving queue handoff overhead (DNS, SIP/RTP, STUN).
	return !d.ShouldUseGoroutineDirectly()
}

// ShouldUseGoroutineDirectly returns true if the traffic should use direct
// goroutine spawn instead of any queue. This is used for:
// 1. DNS traffic (port 53) - drops are unacceptable
// 2. VoIP traffic (SIP/RTP) - extremely latency sensitive
// 3. Other latency/drop-sensitive traffic
func (d UdpFlowDecision) ShouldUseGoroutineDirectly() bool {
	dstPort := d.Key.Dst.Port()
	srcPort := d.Key.Src.Port()

	// DNS (both queries and responses) - never drop
	if dstPort == 53 || srcPort == 53 {
		return true
	}

	// VoIP signaling (SIP) - latency sensitive
	if dstPort == 5060 || srcPort == 5060 {
		return true
	}

	// VoIP media (RTP) - extremely latency sensitive
	if (dstPort >= 5004 && dstPort <= 5060) || (srcPort >= 5004 && srcPort <= 5060) {
		return true
	}

	// STUN - used for NAT traversal, latency sensitive
	if dstPort == 3478 || srcPort == 3478 {
		return true
	}

	return false
}

// DispatchStrategy returns the recommended dispatch strategy for this flow.
func (d UdpFlowDecision) DispatchStrategy() UdpDispatchStrategy {
	if d.ShouldUseOrderedIngress() {
		return StrategyOrderedIngress
	}
	return StrategyDirectGoroutine
}

// UdpDispatchStrategy represents how a UDP packet should be dispatched.
type UdpDispatchStrategy int

const (
	// StrategyDirectGoroutine uses direct goroutine spawn.
	// Lowest latency, no drops, but no concurrency control.
	StrategyDirectGoroutine UdpDispatchStrategy = iota

	// StrategyOrderedIngress uses ordered task pool.
	// Preserves packet ordering within each UDP flow.
	StrategyOrderedIngress
)
