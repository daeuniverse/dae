/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/hex"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

const (
	quicNeedMorePayload1Hex = "" +
		"ce0000000108e8da6ed9f385c987000044d0f34f94dcc26b99261ea264742abe4e552a146e16e89e4b7ef0ab3d6f3a34227b59742e4ba83a1e18cea494d2f67e" +
		"469be4a7ff01334b151e9b7ca63b53735008eecc1f5c618419982292eca5731bb163ba81c1300e0bb99f2536d89ab0faf2dbd37ebfdb3d71f7343296a2190914" +
		"bda556b8f9ccf5219964eb3cd373966fcfaca8a4735fb59fbaf69bbbdfc3a81b11570bb81fd3f5ef780fb7036e0666b997b0f4ed3305b68eafa1a99b3c8a6a214" +
		"2ad9fe1e6b0a0eade6ace92b57416d4bf68fa2e9295bfc22757b0542ce91c8af3f547ef0ad385788db230a50158a0009fd95a7e8ee6e0dd11d6f9a906cbe8117e" +
		"85bd507cdbd8f1a5a6cabf2617de7227d1ae8a8c6086b8ec325df90c0e16b37b4ed0ce617a00c7598a21924a19aec1b08c31b69430b23eefbe555ca2433431d2" +
		"8a4ffec548e463e8e6363b6b4fe9b8477c686c393571273c30b2e1785261faa0fd6f560c12418b27cd0491e013db5a8b3294e01a46a6e4c6b52e32756ab4be6f4" +
		"ebc886c0c472d63f117ce30115182a97f1308c7f28989ce301cabced825154b0f4fa3bf4a55ce2f384ff11d9cbc0460d69db363664f92dc014bdb771b9b1e1ab" +
		"6672c6da71c90aa514dcdc3a4ce45298bf9e5a395ebac3dff2a738c4b4690ee06fdab572a277addac7035d94afe794df05da75a56c79c37f42de1d727dc65e306" +
		"0d9331e2fc82de2d7cef6cb9ae46f648b9930593975c35960b24deb770d5ee4332f8f57a05503399ca7bfdf7207f66a0f73d6b53269a944d5a3043b225adddfd" +
		"d29d20ea8f500bb09ea3bb724083dd29ea8839e8192c4360ba3c5a6db0d695af5d357d6c4ed94aa28305033629201689764189774bbd4f0ae41b878b8f29a0fe" +
		"0e124075ea08c5054871506a05be2f90e9ec0c2db48c0780580312e9ff4071054386e4206841f575f7ca06c228f7ee11e2333d08652b9b4f0b97f473a46a3d79" +
		"c4f9a3416fb20fdbd88cacfa36f06fe1d73618195c6f0bf759a77c6a16b7e271c6cdb672ea53f6edfac860fcaf03313564abde1f66bca441d844d289a9e10257" +
		"11c284f2c7c805353f2a89e9aeb52e3f452e879f0fafcdc0b48a0676afcf617a85037d991762664f6db64847eff2308447c4e8ea6688838bb7237a5fdfe0f169" +
		"5afaa0bbb821b0004585adf151b029bd3458e28ba49dfc17eef1d2dd14ccda88d0848d4cd36d33cc5bab173c2448785ec1bdabc8873c904b95d7847d1b89857f" +
		"2c7e078c6e2eb96029aa91c077e0efcf7b2ed2f30c7abc12189627793c7870dc0e70342cc27402ee1d6dec5ceea0ca06159002ea14a20c63b85689ed1840f404" +
		"e46cb83d91c5e02f3ed938462364d3349f689310234083f7044e4b338ac54bed94530640d684c9688651b915d8c8895ef0f05f376292871b589751ac5b233e3d" +
		"85572bb0c11bbbe91cc49a4ef0422f2676a2f3cc62bc88dbb7acf03cb5e847e976bfca6a90b9cee743ea77be5472ef162ff101c6873043df94c53c252840fd6a" +
		"2662018f0897a06cd215997d6050917876500796fef718957212c773c39d1c7b839931af1e7dfae6e2c1d2251e78896521bb35b20057bad77df85aaed90288c1" +
		"7edb081398815e47239aeb77293a02a61a5125109fc3953593233fa83c17770a815fad7831c1b8647c6089ec621ee774a12a714def498d4335d0bb8a4a6a3ddd" +
		"ead8ddb1176f58218477d55317df88cd2ca5a06b72679cf2ff7253ebd76a5ed3"
	quicNeedMorePayload2Hex = "" +
		"cc0000000108e8da6ed9f385c987000044d026f109c2764c22f0ea2656550ea03e832d0ed5113eff115f2a057f77655cf5bbbb69fc98f7f70a3f407e0d94f379" +
		"60c5ba5bd95a2df75f6f25020c2f2f21ddf9db5266bb4293991d58efec945468a820c61b743ca4b73663c3adcda58dee75607c5465e255b58477069a92868778" +
		"9c18c2ccb53911a47d64b83d5b58398ee4fd58f4f88f78788d5594218730cab9db3bac2fbfb947f2cb4eafb5e2964fce361042c622dfa7130afaf0e9d391ffc3" +
		"aba2f5ee2f5c4d0dfaae0d71db2b3d7fab6dbccbb63d7961ddab55711d5a1beacf00ce5a82030a2c79c4ea65a2762f3b8e5f8fec8f6963b1a42c0f8a8d863225b" +
		"2d6e7a15e9758e43095459e3d7ff88dc276605452b10de95a8795fe9952eb0b1eb200465ca9b00f98e2c4ad6a2a2e2bff2e2430438241525e1d16d5423c22621" +
		"34a97056b7e86d5eb7eb2ac546086a3b8d7a97bc2263fa9a8b46f4b7d31cad63762c17a653b89593434aecf7a5e8fc169cfb5aa4a47e78ee817e115feceb9b68" +
		"b29da6e15c647b7528980fb7cdc7c9ca660871228d0367f030f658d19ddddefe55908a2ec4ef5f5d89ec5aebee33f88a116c2857f7d1a2fd98321f28468a9393" +
		"8da406a68e4e660f0668fe49118812d5264073f28a8aa800c5970ef3f6fb4f0e9e4e48510700a5465c92886c50f2c6af570075f29f6a80636171f73d91864583" +
		"d2d199e39b18623ee0cb489b449838bd9f7cd67ccc3e38f1b5a3ce08814f979f94db45cdcfa39a475e3efc4847def8e8e4c707a88d2f486fc85e10910ab0f1b" +
		"beb40468af777ff2bb0e655f1a006cde0d2e2ae036dafe60f110e859543699e0c9aa47eefa53d792b3cbcfa11ea1d3b55d3629de0345517d47f4e4c801104b81" +
		"710ad28cd8611e150a1fc32160cb784cfcfdd908052cd43969b27929013edd2b0f3cd914590a32b2f99d4fc88873838b6fa0ec1450adb95f395988998801e853" +
		"19fa448925ba767e3191df2b5b0983990beb4127216c93291a94463b453a4972c9a974742b0b22c935f4235c350120b6cf8296fc6d3c2812f74a17acf334e3c3" +
		"4ff9988f980e0cfff737a8b1a03508f47d8bf3748fbb5bd5ad7f1f47120c3a33822612f3a614aae7fe536b73db814aa4aac4b685aa1e7357309cf921b9311136" +
		"24881ce764feeff3292d2d794c6fa76529f3da8e6327e8f28aafe8b675a80ae3f478c65f1bf8fd7f2b140fea130dfa55982f0b0fcd61b42c8b2ea27a2b8bb445" +
		"11eb44c1416ac16698f0ddb739e3d773f2afdd35bcfed0ffd7966aa3e727f8f08d02cab8d034a7ae363e42c9089901ddee147c98a856df4e5dcfeeb2f72e9ed" +
		"b12da513f32d99e1c653f4503e9a7f7fee1f4724ce9d6d530485362d993cb3bc4faff683327a02aee6f004bd9f98a8a4841091d48f5cd27af46431c66e680077" +
		"50be57361e293650a0ae9fc9fa82ddf4483663c9805dc6e4a9b43529c0b2267cc3c0fb9084378acbda4962150a73e0c1b5aef6e40538d2630d8dbc2b084f9a53" +
		"079cc73484906b7ad4a5021f280baf276a01b0fcea57d5c4284364f4d795645fc7bd8bb7d00021af924b75829e8a936e153676a182803537a23c76fee7c881e8" +
		"063751ca0f5a585481b9077e9593734f9997e78b79ba38f6e13a1b631106a2ceddafdf51110b8bf07ec9337024355088d0bb3de2d46a03d3e3e7362b8b815613" +
		"e36d746e5a9992f8e62ad5257e5798bd49b1a62717f02151b75a18e051df1292191d4"
)

func decodeSnifferNeedMorePayload(t *testing.T, encoded string) []byte {
	t.Helper()
	payload, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString(%q): %v", encoded[:16], err)
	}
	return payload
}

func newSnifferNeedMorePayloads(t *testing.T) (first, second []byte) {
	t.Helper()
	return decodeSnifferNeedMorePayload(t, quicNeedMorePayload1Hex),
		decodeSnifferNeedMorePayload(t, quicNeedMorePayload2Hex)
}

func countPooledPacketSniffers(p *PacketSnifferPool) int {
	total := 0
	p.pool.Range(func(_, _ any) bool {
		total++
		return true
	})
	return total
}

func TestHandlePkt_QuicSnifferNeedMoreHoldsFirstPacket(t *testing.T) {
	defer setupQuicInitialRegressionTestState(t)()

	first, _ := newSnifferNeedMorePayloads(t)

	conn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	src, dst, flowDecision := newQuicInitialRegressionFlow(t, first)
	primeQuicRegressionAnyfrom(src, dst)
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}

	if err := cp.handlePkt(nil, first, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("handlePkt(first): %v", err)
	}
	if got := underlay.calls.Load(); got != 0 {
		t.Fatalf("DialContext calls after first NeedMore packet = %d, want 0", got)
	}
	if got := conn.writeCalls.Load(); got != 0 {
		t.Fatalf("WriteTo calls after first NeedMore packet = %d, want 0", got)
	}
	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != 0 {
		t.Fatalf("pooled udp endpoints after first NeedMore packet = %d, want 0", got)
	}

	snifferKey := NewPacketSnifferKey(src, dst, first)
	sniffer := DefaultPacketSnifferSessionMgr.Get(snifferKey)
	if sniffer == nil {
		t.Fatal("expected DCID-specific sniffer session after first NeedMore packet")
		return
	}
	if got := countPooledPacketSniffers(DefaultPacketSnifferSessionMgr); got != 1 {
		t.Fatalf("pooled packet sniffers after first NeedMore packet = %d, want 1", got)
	}
	if got := DefaultPacketSnifferSessionMgr.Get(UdpFlowKey{Src: src, Dst: dst}.PacketSnifferKey()); got != nil {
		t.Fatal("expected no coarse src/dst sniffer alias alongside the DCID-specific session")
	}
	sniffer.Mu.Lock()
	defer sniffer.Mu.Unlock()
	if !sniffer.NeedMore() {
		t.Fatal("expected sniffer to remain in NeedMore state after first packet")
	}
	if got := len(sniffer.Data()); got != 2 {
		t.Fatalf("sniffer buffered packet count = %d, want 2 (empty sentinel + first packet)", got)
	}
	if got := len(sniffer.Data()[1]); got != len(first) {
		t.Fatalf("buffered first packet length = %d, want %d", got, len(first))
	}
}

func TestClassifyUdpFlow_SiblingPacketUsesFlowFamilySnifferSession(t *testing.T) {
	defer setupQuicInitialRegressionTestState(t)()

	src := mustParseAddrPort("192.168.89.3:42688")
	dst := mustParseAddrPort("52.199.194.44:443")
	initialLikePayload := makeLikelyQuicInitialPayload(0x55)
	initialDecision := ClassifyUdpFlow(src, dst, initialLikePayload).EnsureSnifferSession()
	if !initialDecision.IsQuicInitial {
		t.Fatal("expected Initial-shaped payload on sniff port to enter the QUIC Initial path")
	}
	if !initialDecision.HasSnifferSession {
		t.Fatal("expected EnsureSnifferSession to mark the flow as having a sniffer session")
	}

	exactKey := NewPacketSnifferKey(src, dst, initialLikePayload)
	if got := DefaultPacketSnifferSessionMgr.Get(exactKey); got == nil {
		t.Fatal("expected exact DCID-specific sniffer session to exist")
	}

	ordinaryPayload := []byte{0x10, 0x20, 0x30, 0x40}
	siblingDecision := ClassifyUdpFlow(src, dst, ordinaryPayload)
	if siblingDecision.IsQuicInitial {
		t.Fatal("expected ordinary sibling packet to avoid QUIC Initial classification")
	}
	if !siblingDecision.HasSnifferSession {
		t.Fatal("expected sibling packet to observe flow-family sniffer state")
	}
	if !siblingDecision.ShouldUseOrderedIngress() {
		t.Fatal("expected sibling packet with flow-family sniffer state to use ordered ingress")
	}
	if got := siblingDecision.EndpointKeyForInitialLookup(); got != (UdpEndpointKey{Src: src, Dst: dst}) {
		t.Fatalf("initial lookup key = %+v, want symmetric key", got)
	}
	if got := DefaultPacketSnifferSessionMgr.Get(siblingDecision.PacketSnifferKey()); got != nil {
		t.Fatal("expected sibling packet to rely on flow-family state, not a coarse sniffer alias entry")
	}
}

func TestHandlePkt_QuicSnifferCompletionReplaysBufferedPackets(t *testing.T) {
	defer setupQuicInitialRegressionTestState(t)()

	first, second := newSnifferNeedMorePayloads(t)

	conn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	src, dst, flowDecision := newQuicInitialRegressionFlow(t, first)
	primeQuicRegressionAnyfrom(src, dst)
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}

	if err := cp.handlePkt(nil, first, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("handlePkt(first): %v", err)
	}

	secondDecision := ClassifyUdpFlow(src, dst, second).EnsureSnifferSession()
	if !secondDecision.IsQuicInitial {
		t.Fatal("expected second payload to stay on QUIC Initial path")
	}
	if err := cp.handlePkt(nil, second, src, dst, routingResult, secondDecision, false); err != nil {
		t.Fatalf("handlePkt(second): %v", err)
	}

	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after sniffer completion = %d, want 1", got)
	}
	if got := conn.writeCalls.Load(); got != 2 {
		t.Fatalf("WriteTo calls after replaying first+second packet = %d, want 2", got)
	}
	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != 1 {
		t.Fatalf("pooled udp endpoints after sniffer completion = %d, want 1", got)
	}

	snifferKey := NewPacketSnifferKey(src, dst, second)
	sniffer := DefaultPacketSnifferSessionMgr.Get(snifferKey)
	if sniffer == nil {
		t.Fatal("expected sniffer session to remain as lightweight flow state after completion")
		return
	}
	sniffer.Mu.Lock()
	defer sniffer.Mu.Unlock()
	if sniffer.NeedMore() {
		t.Fatal("expected completed sniffer session to exit NeedMore state")
	}
	if got := len(sniffer.Data()); got != 1 {
		t.Fatalf("completed sniffer buffered packet count = %d, want 1 sentinel after compaction", got)
	}
	if got := len(sniffer.Data()[0]); got != 0 {
		t.Fatalf("completed sniffer sentinel length = %d, want 0", got)
	}
}

func TestHandlePkt_QuicSnifferCompletionReplaysAllBufferedPackets(t *testing.T) {
	defer setupQuicInitialRegressionTestState(t)()

	first, second := newSnifferNeedMorePayloads(t)

	conn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	src, dst, flowDecision := newQuicInitialRegressionFlow(t, first)
	primeQuicRegressionAnyfrom(src, dst)
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}

	if err := cp.handlePkt(nil, first, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("handlePkt(first #1): %v", err)
	}
	if err := cp.handlePkt(nil, first, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("handlePkt(first #2): %v", err)
	}

	secondDecision := ClassifyUdpFlow(src, dst, second).EnsureSnifferSession()
	if err := cp.handlePkt(nil, second, src, dst, routingResult, secondDecision, false); err != nil {
		t.Fatalf("handlePkt(second): %v", err)
	}

	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after replaying three buffered packets = %d, want 1", got)
	}
	if got := conn.writeCalls.Load(); got != 3 {
		t.Fatalf("WriteTo calls after replaying first+first+second packet = %d, want 3", got)
	}
}

func TestHandlePkt_QuicSnifferRemovalDropsBufferedPacket(t *testing.T) {
	defer setupQuicInitialRegressionTestState(t)()

	first, second := newSnifferNeedMorePayloads(t)

	conn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	src, dst, flowDecision := newQuicInitialRegressionFlow(t, first)
	primeQuicRegressionAnyfrom(src, dst)
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}

	if err := cp.handlePkt(nil, first, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("handlePkt(first before removal): %v", err)
	}

	snifferKey := NewPacketSnifferKey(src, dst, first)
	sniffer := DefaultPacketSnifferSessionMgr.Get(snifferKey)
	if sniffer == nil {
		t.Fatal("expected sniffer session before removal")
	}
	if err := DefaultPacketSnifferSessionMgr.Remove(snifferKey, sniffer); err != nil {
		t.Fatalf("Remove(sniffer): %v", err)
	}
	if got := DefaultPacketSnifferSessionMgr.Get(snifferKey); got != nil {
		t.Fatal("expected sniffer session to be removed")
	}

	// Retransmit the first packet after the buffered state has been lost, then
	// complete sniffing with the second packet. Without the removal above, this
	// sequence would replay three packets. After removal, only the retransmitted
	// first packet and the second packet survive.
	if err := cp.handlePkt(nil, first, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("handlePkt(first after removal): %v", err)
	}
	secondDecision := ClassifyUdpFlow(src, dst, second).EnsureSnifferSession()
	if err := cp.handlePkt(nil, second, src, dst, routingResult, secondDecision, false); err != nil {
		t.Fatalf("handlePkt(second after removal): %v", err)
	}

	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after removal/recovery = %d, want 1", got)
	}
	if got := conn.writeCalls.Load(); got != 2 {
		t.Fatalf("WriteTo calls after removal/recovery = %d, want 2 (one buffered packet was lost)", got)
	}
}
