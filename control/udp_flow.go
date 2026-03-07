/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"

	"github.com/daeuniverse/dae/component/sniffing"
)

// UdpFlowKey identifies a UDP flow at ingress.
// We intentionally include destination so ordered processing stays scoped to
// a single flow instead of serializing all traffic sharing the same source port.
type UdpFlowKey struct {
	Src netip.AddrPort
	Dst netip.AddrPort
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

func (k UdpFlowKey) FullConeNatEndpointKey() UdpEndpointKey {
	return UdpEndpointKey{Src: k.Src}
}

// UdpFlowDecision centralizes the cheap ingress classification that is shared
// across scheduling, sniffing, and UDP endpoint selection.
type UdpFlowDecision struct {
	Key               UdpFlowKey
	HasSnifferSession bool
	IsQuicInitial     bool
}

func ClassifyUdpFlow(src, dst netip.AddrPort, data []byte) UdpFlowDecision {
	key := NewUdpFlowKey(src, dst)
	return UdpFlowDecision{
		Key:               key,
		HasSnifferSession: DefaultPacketSnifferSessionMgr.Get(key.PacketSnifferKey()) != nil,
		IsQuicInitial:     sniffing.IsLikelyQuicInitialPacket(data),
	}
}

func (d UdpFlowDecision) PacketSnifferKey() PacketSnifferKey {
	return d.Key.PacketSnifferKey()
}

func (d UdpFlowDecision) SymmetricNatEndpointKey() UdpEndpointKey {
	return d.Key.SymmetricNatEndpointKey()
}

func (d UdpFlowDecision) FullConeNatEndpointKey() UdpEndpointKey {
	return d.Key.FullConeNatEndpointKey()
}

func (d UdpFlowDecision) CachedRoutingEndpointKey() UdpEndpointKey {
	return d.FullConeNatEndpointKey()
}

func (d UdpFlowDecision) EndpointKeyForDial(domain string) UdpEndpointKey {
	if domain != "" || d.PreferSymmetricNat() {
		return d.SymmetricNatEndpointKey()
	}
	return d.FullConeNatEndpointKey()
}

func (d UdpFlowDecision) EnsureSnifferSession() UdpFlowDecision {
	if d.HasSnifferSession || !d.IsQuicInitial {
		return d
	}
	_, _ = DefaultPacketSnifferSessionMgr.GetOrCreate(d.PacketSnifferKey(), nil)
	d.HasSnifferSession = true
	return d
}

func (d UdpFlowDecision) PreferSymmetricNat() bool {
	return d.IsQuicInitial
}

func (d UdpFlowDecision) ShouldAttemptSniff() bool {
	return d.HasSnifferSession || d.IsQuicInitial
}

func (d UdpFlowDecision) ShouldUseOrderedIngress() bool {
	return d.HasSnifferSession || d.IsQuicInitial
}
