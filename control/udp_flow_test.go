/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUdpFlowDecision_EndpointKeys(t *testing.T) {
	src := netip.MustParseAddrPort("192.168.1.10:12345")
	dst := netip.MustParseAddrPort("93.184.216.34:443")
	decision := ClassifyUdpFlow(src, dst, []byte{0x00, 0x01, 0x02, 0x03})

	// Port 443 triggers PreferSymmetricNat via IsLikelyQuicData
	// So CachedRoutingEndpointKey returns SymmetricNatEndpointKey {Src, Dst}
	require.Equal(t, UdpEndpointKey{Src: src, Dst: dst}, decision.CachedRoutingEndpointKey())
	// EndpointKeyForDial also returns SymmetricNatEndpointKey for port 443
	require.Equal(t, UdpEndpointKey{Src: src, Dst: dst}, decision.EndpointKeyForDial(""))
	require.Equal(t, UdpEndpointKey{Src: src, Dst: dst}, decision.EndpointKeyForDial("example.com"))
	require.Equal(t, UdpEndpointKey{Src: src, Dst: dst}, decision.SymmetricNatEndpointKey())
	require.Equal(t, UdpEndpointKey{Src: src}, decision.FullConeNatEndpointKey())
}

func TestUdpFlowDecision_ExistingSnifferSessionUsesOrderedIngress(t *testing.T) {
	resetPacketSnifferPoolForTest()

	src := netip.MustParseAddrPort("10.0.0.1:12000")
	dst := netip.MustParseAddrPort("8.8.8.8:443")
	data := []byte{0x00, 0x01, 0x02, 0x03}

	decision := ClassifyUdpFlow(src, dst, data)
	require.False(t, decision.IsQuicInitial)
	require.False(t, decision.HasSnifferSession)
	// Optimized: Port 443 no longer forces ordered ingress for non-QUIC traffic
	require.False(t, decision.ShouldUseOrderedIngress())
	require.False(t, decision.ShouldAttemptSniff()) // ShouldAttemptSniff only checks IsQuicInitial or HasSnifferSession

	sniffer, _ := DefaultPacketSnifferSessionMgr.GetOrCreate(decision.PacketSnifferKey(), nil)
	defer DefaultPacketSnifferSessionMgr.Remove(decision.PacketSnifferKey(), sniffer)

	decision = ClassifyUdpFlow(src, dst, data)
	require.True(t, decision.HasSnifferSession)
	// With sniffer session, ordered ingress IS used
	require.True(t, decision.ShouldUseOrderedIngress())
	require.True(t, decision.ShouldAttemptSniff())
}

func TestUdpFlowDecision_EnsureSnifferSessionForQuicInitial(t *testing.T) {
	resetPacketSnifferPoolForTest()

	src := netip.MustParseAddrPort("10.0.0.2:22000")
	dst := netip.MustParseAddrPort("1.1.1.1:443")
	quicInitialPacket := []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00}

	decision := ClassifyUdpFlow(src, dst, quicInitialPacket)
	require.True(t, decision.IsQuicInitial)
	require.False(t, decision.HasSnifferSession)

	decision = decision.EnsureSnifferSession()
	require.True(t, decision.HasSnifferSession)
	require.True(t, decision.ShouldUseOrderedIngress())
	require.True(t, decision.ShouldAttemptSniff())

	sniffer := DefaultPacketSnifferSessionMgr.Get(decision.PacketSnifferKey())
	require.NotNil(t, sniffer)
	require.NoError(t, DefaultPacketSnifferSessionMgr.Remove(decision.PacketSnifferKey(), sniffer))
}

func BenchmarkClassifyUdpFlow_NoSnifferSession(b *testing.B) {
	resetPacketSnifferPoolForTest()

	src := netip.MustParseAddrPort("10.0.0.10:12000")
	dst := netip.MustParseAddrPort("8.8.8.8:443")
	data := []byte{0x00, 0x01, 0x02, 0x03}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decision := ClassifyUdpFlow(src, dst, data)
		if decision.HasSnifferSession || decision.IsQuicInitial {
			b.Fatal("unexpected classification result")
		}
	}
}

func BenchmarkClassifyUdpFlow_WithSnifferSession(b *testing.B) {
	resetPacketSnifferPoolForTest()

	src := netip.MustParseAddrPort("10.0.0.11:12001")
	dst := netip.MustParseAddrPort("1.1.1.1:443")
	flowKey := NewUdpFlowKey(src, dst)
	sniffer, _ := DefaultPacketSnifferSessionMgr.GetOrCreate(flowKey.PacketSnifferKey(), &PacketSnifferOptions{Ttl: time.Second})
	defer DefaultPacketSnifferSessionMgr.Remove(flowKey.PacketSnifferKey(), sniffer)
	data := []byte{0x00, 0x01, 0x02, 0x03}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decision := ClassifyUdpFlow(src, dst, data)
		if !decision.HasSnifferSession {
			b.Fatal("expected existing sniff session")
		}
	}
}

func BenchmarkUdpFlowDecision_QuicHandshakeLifecycle(b *testing.B) {
	resetPacketSnifferPoolForTest()

	serverAddr := netip.MustParseAddrPort("40.99.33.130:443")
	baseClientAddr := netip.MustParseAddrPort("10.0.0.20:20000")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		clientAddr := netip.AddrPortFrom(baseClientAddr.Addr(), uint16(20000+(i%40000)))

		initialDecision := ClassifyUdpFlow(clientAddr, serverAddr, sniffTestQuicPacket2)
		if !initialDecision.IsQuicInitial {
			b.Fatal("expected QUIC Initial classification for first fragment")
		}
		initialDecision = initialDecision.EnsureSnifferSession()
		if !initialDecision.HasSnifferSession || !initialDecision.ShouldUseOrderedIngress() {
			b.Fatal("initial QUIC fragment should enter ordered ingress with sniff session")
		}

		sniffer := DefaultPacketSnifferSessionMgr.Get(initialDecision.PacketSnifferKey())
		if sniffer == nil {
			b.Fatal("expected sniff session after EnsureSnifferSession")
		}

		sniffer.AppendData(sniffTestQuicPacket2)
		_, _ = sniffer.SniffUdp()

		followDecision := ClassifyUdpFlow(clientAddr, serverAddr, sniffTestQuicPacket1)
		if !followDecision.HasSnifferSession || !followDecision.ShouldUseOrderedIngress() {
			b.Fatal("follow-up QUIC fragment should stay on ordered ingress")
		}

		sniffer.AppendData(sniffTestQuicPacket1)
		_, _ = sniffer.SniffUdp()

		if err := DefaultPacketSnifferSessionMgr.Remove(initialDecision.PacketSnifferKey(), sniffer); err != nil {
			b.Fatal(err)
		}
	}
}
