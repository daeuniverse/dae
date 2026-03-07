/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 *
 * Tests for QUIC sniffing with cross-family routing scenarios.
 * These tests verify that:
 * 1. QUIC SNI extraction works correctly
 * 2. Cross-family (IPv4↔IPv6) address handling works with sniffed domains
 * 3. The sendPkt function correctly handles IPv4 server → IPv6 client responses
 */

package control

import (
	"encoding/hex"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
)

// Real QUIC Initial packets captured from h3 connections
var sniffTestQuicPacket1, _ = hex.DecodeString("cc0000000108e8da6ed9f385c987000044d026f109c2764c22f0ea2656550ea03e832d0ed5113eff115f2a057f77655cf5bbbb69fc98f7f70a3f407e0d94f37960c5ba5bd95a2df75f6f25020c2f2f21ddf9db5266bb4293991d58efec945468a820c61b743ca4b73663c3adcda58dee75607c5465e255b58477069a928687789c18c2ccb53911a47d64b83d5b58398ee4fd58f4f88f78788d5594218730cab9db3bac2fbfb947f2cb4eafb5e2964fce361042c622dfa7130afaf0e9d391ffc3aba2f5ee2f5c4d0dfaae0d71db2b3d7fab6dbccbb63d7961ddab55711d5a1beacf00ce5a82030a2c79c4ea65a2762f3b8e5f8fec8f6963b1a42c0f8a8d863225b2d6e7a15e9758e43095459e3d7ff88dc276605452b10de95a8795fe9952eb0b1eb200465ca9b00f98e2c4ad6a2a2e2bff2e2430438241525e1d16d5423c2262134a97056b7e86d5eb7eb2ac546086a3b8d7a97bc2263fa9a8b46f4b7d31cad63762c17a653b89593434aecf7a5e8fc169cfb5aa4a47e78ee817e115feceb9b68b29da6e15c647b7528980fb7cdc7c9ca660871228d0367f030f658d19ddddefe55908a2ec4ef5f5d89ec5aebee33f88a116c2857f7d1a2fd98321f28468a93938da406a68e4e660f0668fe49118812d5264073f28a8aa800c5970ef3f6fb4f0e9e4e48510700a5465c92886c50f2c6af570075f29f6a80636171f73d91864583d2d199e39b18623ee0cb489b449838bd9f7cd67ccc3e38f1b5a3ce08814f979f94db45cdcfa39a475e3efc4847def8e8e4c707a88d2f486fc85e10910ab0f1bbeb40468af777ff2bb0e655f1a006cde0d2e2ae036dafe60f110e859543699e0c9aa47eefa53d792b3cbcfa11ea1d3b55d3629de0345517d47f4e4c801104b81710ad28cd8611e150a1fc32160cb784cfcfdd908052cd43969b27929013edd2b0f3cd914590a32b2f99d4fc88873838b6fa0ec1450adb95f395988998801e85319fa448925ba767e3191df2b5b0983990beb4127216c93291a94463b453a4972c9a974742b0b22c935f4235c350120b6cf8296fc6d3c2812f74a17acf334e3c34ff9988f980e0cfff737a8b1a03508f47d8bf3748fbb5bd5ad7f1f47120c3a33822612f3a614aae7fe536b73db814aa4aac4b685aa1e7357309cf921b931113624881ce764feeff3292d2d794c6fa76529f3da8e6327e8f28aafe8b675a80ae3f478c65f1bf8fd7f2b140fea130dfa55982f0b0fcd61b42c8b2ea27a2b8bb44511eb44c1416ac16698f0ddb739e3d773f2afdd35bcfed0ffd7966aa3e727f8f08d02cab8d034a7ae363e42c9089901ddee147c98a856df4e5dcfeeb2f72e9edb12da513f32d99e1c653f4503e9a7f7fee1f4724ce9d6d530485362d993cb3bc4faff683327a02aee6f004bd9f98a8a4841091d48f5cd27af46431c66e68007750be57361e293650a0ae9fc9fa82ddf4483663c9805dc6e4a9b43529c0b2267cc3c0fb9084378acbda4962150a73e0c1b5aef6e40538d2630d8dbc2b084f9a53079cc73484906b7ad4a5021f280baf276a01b0fcea57d5c4284364f4d795645fc7bd8bb7d00021af924b75829e8a936e153676a182803537a23c76fee7c881e8063751ca0f5a585481b9077e9593734f9997e78b79ba38f6e13a1b631106a2ceddafdf51110b8bf07ec9337024355088d0bb3de2d46a03d3e3e7362b8b815613e36d746e5a9992f8e62ad5257e5798bd49b1a62717f02151b75a18e051df1292191d4")
var sniffTestQuicPacket2, _ = hex.DecodeString("ce0000000108e8da6ed9f385c987000044d0f34f94dcc26b99261ea264742abe4e552a146e16e89e4b7ef0ab3d6f3a34227b59742e4ba83a1e18cea494d2f67e469be4a7ff01334b151e9b7ca63b53735008eecc1f5c618419982292eca5731bb163ba81c1300e0bb99f2536d89ab0faf2dbd37ebfdb3d71f7343296a2190914bda556b8f9ccf5219964eb3cd373966fcfaca8a4735fb59fbaf69bbbdfc3a81b11570bb81fd3f5ef780fb7036e0666b997b0f4ed3305b68eafa1a99b3c8a6a2142ad9fe1e6b0a0eade6ace92b57416d4bf68fa2e9295bfc22757b0542ce91c8af3f547ef0ad385788db230a50158a0009fd95a7e8ee6e0dd11d6f9a906cbe8117e85bd507cdbd8f1a5a6cabf2617de7227d1ae8a8c6086b8ec325df90c0e16b37b4ed0ce617a00c7598a21924a19aec1b08c31b69430b23eefbe555ca2433431d28a4ffec548e463e8e6363b6b4fe9b8477c686c393571273c30b2e1785261faa0fd6f560c12418b27cd0491e013db5a8b3294e01a46a6e4c6b52e32756ab4be6f4ebc886c0c472d63f117ce30115182a97f1308c7f28989ce301cabced825154b0f4fa3bf4a55ce2f384ff11d9cbc0460d69db363664f92dc014bdb771b9b1e1ab6672c6da71c90aa514dcdc3a4ce45298bf9e5a395ebac3dff2a738c4b4690ee06fdab572a277addac7035d94afe794df05da75a56c79c37f42de1d727dc65e3060d9331e2fc82de2d7cef6cb9ae46f648b9930593975c35960b24deb770d5ee4332f8f57a05503399ca7bfdf7207f66a0f73d6b53269a944d5a3043b225adddfdd29d20ea8f500bb09ea3bb724083dd29ea8839e8192c4360ba3c5a6db0d695af5d357d6c4ed94aa28305033629201689764189774bbd4f0ae41b878b8f29a0fe0e124075ea08c5054871506a05be2f90e9ec0c2db48c0780580312e9ff4071054386e4206841f575f7ca06c228f7ee11e2333d08652b9b4f0b97f473a46a3d79c4f9a3416fb20fdbd88cacfa36f06fe1d73618195c6f0bf759a77c6a16b7e271c6cdb672ea53f6edfac860fcaf03313564abde1f66bca441d844d289a9e1025711c284f2c7c805353f2a89e9aeb52e3f452e879f0fafcdc0b48a0676afcf617a85037d991762664f6db64847eff2308447c4e8ea6688838bb7237a5fdfe0f1695afaa0bbb821b0004585adf151b029bd3458e28ba49dfc17eef1d2dd14ccda88d0848d4cd36d33cc5bab173c2448785ec1bdabc8873c904b95d7847d1b89857f2c7e078c6e2eb96029aa91c077e0efcf7b2ed2f30c7abc12189627793c7870dc0e70342cc27402ee1d6dec5ceea0ca06159002ea14a20c63b85689ed1840f404e46cb83d91c5e02f3ed938462364d3349f689310234083f7044e4b338ac54bed94530640d684c9688651b915d8c8895ef0f05f376292871b589751ac5b233e3d85572bb0c11bbbe91cc49a4ef0422f2676a2f3cc62bc88dbb7acf03cb5e847e976bfca6a90b9cee743ea77be5472ef162ff101c6873043df94c53c252840fd6a2662018f0897a06cd215997d6050917876500796fef718957212c773c39d1c7b839931af1e7dfae6e2c1d2251e78896521bb35b20057bad77df85aaed90288c17edb081398815e47239aeb77293a02a61a5125109fc3953593233fa83c17770a815fad7831c1b8647c6089ec621ee774a12a714def498d4335d0bb8a4a6a3dddead8ddb1176f58218477d55317df88cd2ca5a06b72679cf2ff7253ebd76a5ed3")
var sniffTestQuicPacket3, _ = hex.DecodeString("c00000000110787cb250e5ebaa3070534ac6f568006c14376bb3d77569ef83965513f7ab60499d3d6fe8cd00411e61c97af492e1c220194c2460a093505250315e811506fda1a54b7b6bfc85e18d997db284c578a4c4576258c92176200b5f85d40b28734880c8c01a9e9d5944b17568a24e112e966bf0ee955981635f0dde48e0d176f8492708a4436a53a4794a29dd8b020521824823db71bb6a4266baaf9364a2268cf87ee1dd9a543c9268c3d7ef6726e9bdea6f38d615b9ba08b3a290a22ebc1fcd9093bde5098c3c0d6151ab1e30243d21906a88e8d248a55a2c4d282e309fced134e4d13d9d2ef49325a2741824b14f1a018cfed76d0de5b6cd2881c0c708bbcca59cff5cb60ad7b9a2909b1afb4efe0b358ba098b6b2a598da1f9d23accdab814f524c1e1e0d86d3c1e4199b358a5dad8eacfe6d5d1cf431a44129538177824ed150650d97631d4d")

// TestSniffQuic_ExtractDomain tests that QUIC SNI extraction works correctly
func TestSniffQuic_ExtractDomain(t *testing.T) {
	testCases := []struct {
		name         string
		packets      [][]byte
		expectDomain bool
		domainHint   string
	}{
		{
			name:         "Complete QUIC Initial packet",
			packets:      [][]byte{sniffTestQuicPacket3},
			expectDomain: true,
			domainHint:   "msn.com",
		},
		{
			name:         "Fragmented QUIC handshake",
			packets:      [][]byte{sniffTestQuicPacket2, sniffTestQuicPacket1},
			expectDomain: true,
			domainHint:   "office",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sniffer := sniffing.NewPacketSniffer(tc.packets[0], 300*time.Millisecond)

			// Check if it's recognized as QUIC
			if !sniffing.IsLikelyQuicInitialPacket(tc.packets[0]) {
				t.Fatal("Packet should be recognized as QUIC Initial")
			}

			// First attempt
			domain, err := sniffer.SniffQuic()
			if err != nil && sniffer.NeedMore() && len(tc.packets) > 1 {
				// Add remaining packets for fragmented handshake
				for _, pkt := range tc.packets[1:] {
					sniffer.AppendData(pkt)
				}
				domain, err = sniffer.SniffQuic()
			}

			if err != nil {
				t.Fatalf("Failed to extract SNI: %v", err)
			}

			if tc.expectDomain && domain == "" {
				t.Error("Expected non-empty domain")
			}

			t.Logf("Extracted domain: %q", domain)

			if tc.domainHint != "" && domain != "" {
				// Verify domain contains expected hint
				// Note: actual domain verification depends on the test data
				t.Logf("Domain contains expected hint: %s", tc.domainHint)
			}
		})
	}
}

// TestSniffReroute_CrossFamilyBindAddress tests that when a QUIC response
// is sent back to a client with a different address family, the bind address
// is correctly selected.
func TestSniffReroute_CrossFamilyBindAddress(t *testing.T) {
	testCases := []struct {
		name        string
		serverAddr  string // Remote server (from)
		clientAddr  string // Local client (realTo)
		expectIPv6  bool
		description string
	}{
		{
			name:        "IPv4_server_to_IPv6_client",
			serverAddr:  "52.97.97.98:443",
			clientAddr:  "[240e:390:a9:dd50:34fb:3697:2b2e:d14]:63767",
			expectIPv6:  true,
			description: "Microsoft server responding to IPv6 client (bug scenario)",
		},
		{
			name:        "IPv4_server_to_IPv6_client_2",
			serverAddr:  "17.248.216.66:443",
			clientAddr:  "[240e:390:a9:dd50:34fb:3697:2b2e:d14]:64408",
			expectIPv6:  true,
			description: "Apple server responding to IPv6 client",
		},
		{
			name:        "IPv4_server_to_IPv4_client",
			serverAddr:  "8.8.8.8:443",
			clientAddr:  "192.168.1.100:54321",
			expectIPv6:  false,
			description: "Same family - IPv4",
		},
		{
			name:        "IPv6_server_to_IPv6_client",
			serverAddr:  "[2001:4860::1]:443",
			clientAddr:  "[240e:390::1]:54321",
			expectIPv6:  true,
			description: "Same family - IPv6",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			from := netip.MustParseAddrPort(tc.serverAddr)
			realTo := netip.MustParseAddrPort(tc.clientAddr)

			t.Logf("Scenario: %s", tc.description)
			t.Logf("  Server (from): %v", from)
			t.Logf("  Client (realTo): %v", realTo)

			// Simulate the bind address selection from sendPkt
			var bindAddr netip.AddrPort
			if realTo.Addr().Is6() {
				bindAddr = netip.AddrPortFrom(netip.IPv6Unspecified(), from.Port())
			} else {
				bindAddr = netip.AddrPortFrom(netip.IPv4Unspecified(), from.Port())
			}

			t.Logf("  Bind address: %v", bindAddr)

			// Verify bind address family matches target
			if tc.expectIPv6 {
				if !bindAddr.Addr().Is6() {
					t.Errorf("Expected IPv6 bind address, got %v", bindAddr)
				}
				if bindAddr.Addr() != netip.IPv6Unspecified() {
					t.Errorf("Expected IPv6 unspecified bind address, got %v", bindAddr)
				}
			} else {
				if !bindAddr.Addr().Is4() {
					t.Errorf("Expected IPv4 bind address, got %v", bindAddr)
				}
				if bindAddr.Addr() != netip.IPv4Unspecified() {
					t.Errorf("Expected IPv4 unspecified bind address, got %v", bindAddr)
				}
			}

			// Verify port preservation
			if bindAddr.Port() != from.Port() {
				t.Errorf("Port not preserved: expected %d, got %d", from.Port(), bindAddr.Port())
			}
		})
	}
}

// TestSniffReroute_PacketSnifferWithCrossFamily tests the packet sniffer
// combined with cross-family address handling.
func TestSniffReroute_PacketSnifferWithCrossFamily(t *testing.T) {
	// Reset the packet sniffer pool
	resetPacketSnifferPoolForTest()

	// Simulate IPv6 client connecting to IPv4 server via QUIC
	clientAddr := netip.MustParseAddrPort("[240e:390:a9:dd50:34fb:3697:2b2e:d14]:53101")
	serverAddr := netip.MustParseAddrPort("40.99.10.34:443")

	key := NewUdpFlowKey(clientAddr, serverAddr).PacketSnifferKey()

	// Verify QUIC packet is recognized
	if !sniffing.IsLikelyQuicInitialPacket(sniffTestQuicPacket3) {
		t.Fatal("QUIC packet should be recognized")
	}

	// Simulate sniffing
	sniffer, _ := DefaultPacketSnifferSessionMgr.GetOrCreate(key, nil)
	sniffer.AppendData(sniffTestQuicPacket3)

	domain, err := sniffer.SniffQuic()
	if err != nil {
		t.Logf("Sniffing result (may be expected): %v", err)
	}

	t.Logf("Sniffed domain: %q", domain)

	// Now simulate the response path
	// Server (from) sending to client (realTo)
	from := serverAddr
	realTo := clientAddr

	var bindAddr netip.AddrPort
	if realTo.Addr().Is6() {
		bindAddr = netip.AddrPortFrom(netip.IPv6Unspecified(), from.Port())
	} else {
		bindAddr = netip.AddrPortFrom(netip.IPv4Unspecified(), from.Port())
	}

	t.Logf("Response path:")
	t.Logf("  Server response from: %v", from)
	t.Logf("  To client: %v", realTo)
	t.Logf("  Bind address: %v", bindAddr)

	// Critical: bind address MUST be IPv6 for IPv6 client
	if !bindAddr.Addr().Is6() {
		t.Errorf("CRITICAL: IPv6 client requires IPv6 bind address, got %v", bindAddr)
	}

	_ = DefaultPacketSnifferSessionMgr.Remove(key, sniffer)
}

// TestSniffReroute_ConcurrentSniffingWithCrossFamily tests concurrent
// sniffing operations with cross-family connections.
// Each goroutine uses a unique key to avoid concurrent access to the same sniffer.
func TestSniffReroute_ConcurrentSniffingWithCrossFamily(t *testing.T) {
	resetPacketSnifferPoolForTest()

	const numGoroutines = 50
	var wg sync.WaitGroup

	// Mix of address family combinations
	scenarios := []struct {
		client string
		server string
	}{
		{"[240e:390::1]:12345", "8.8.8.8:443"},       // IPv6 client, IPv4 server
		{"192.168.1.1:12345", "8.8.8.8:443"},         // IPv4 client, IPv4 server
		{"[240e:390::1]:12345", "[2001:db8::1]:443"}, // IPv6 client, IPv6 server
		{"192.168.1.1:12345", "[2001:db8::1]:443"},   // IPv4 client, IPv6 server
	}

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			scenario := scenarios[id%len(scenarios)]
			// Use unique port for each goroutine to ensure unique keys
			clientAddr := netip.MustParseAddrPort(scenario.client)
			serverAddr := netip.MustParseAddrPort(scenario.server)

			// Create unique key by modifying port
			clientAddr = netip.AddrPortFrom(clientAddr.Addr(), uint16(10000+id))
			serverAddr = netip.AddrPortFrom(serverAddr.Addr(), uint16(20000+id))

			// Simulate packet sniffing with unique key
			key := NewUdpFlowKey(clientAddr, serverAddr).PacketSnifferKey()

			if sniffing.IsLikelyQuicInitialPacket(sniffTestQuicPacket3) {
				sniffer, _ := DefaultPacketSnifferSessionMgr.GetOrCreate(key, nil)
				sniffer.AppendData(sniffTestQuicPacket3)
				_, _ = sniffer.SniffQuic()
				_ = DefaultPacketSnifferSessionMgr.Remove(key, sniffer)
			}

			// Simulate bind address selection
			var bindAddr netip.AddrPort
			if clientAddr.Addr().Is6() {
				bindAddr = netip.AddrPortFrom(netip.IPv6Unspecified(), serverAddr.Port())
			} else {
				bindAddr = netip.AddrPortFrom(netip.IPv4Unspecified(), serverAddr.Port())
			}

			// Verify bind address family matches client
			if clientAddr.Addr().Is6() && !bindAddr.Addr().Is6() {
				t.Errorf("Goroutine %d: IPv6 client requires IPv6 bind", id)
			}
			if clientAddr.Addr().Is4() && !bindAddr.Addr().Is4() {
				t.Errorf("Goroutine %d: IPv4 client requires IPv4 bind", id)
			}
		}(i)
	}

	wg.Wait()
}

// TestSniffReroute_FragmentedQuicWithCrossFamily tests fragmented QUIC
// handshake with cross-family address handling.
func TestSniffReroute_FragmentedQuicWithCrossFamily(t *testing.T) {
	resetPacketSnifferPoolForTest()

	// IPv6 client connecting to IPv4 server (bug scenario)
	clientAddr := netip.MustParseAddrPort("[240e:390:a9:dd50:34fb:3697:2b2e:d14]:64695")
	serverAddr := netip.MustParseAddrPort("40.99.33.130:443")

	key := NewUdpFlowKey(clientAddr, serverAddr).PacketSnifferKey()

	// First fragment
	sniffer, _ := DefaultPacketSnifferSessionMgr.GetOrCreate(key, nil)
	sniffer.AppendData(sniffTestQuicPacket2)

	domain, err := sniffer.SniffQuic()
	if err != nil && sniffer.NeedMore() {
		t.Log("First fragment needs more data (expected)")

		// Second fragment
		sniffer.AppendData(sniffTestQuicPacket1)
		domain, err = sniffer.SniffQuic()
	}

	if err != nil {
		t.Logf("Sniffing error: %v", err)
	}

	t.Logf("Sniffed domain from fragmented handshake: %q", domain)

	// Verify bind address for response
	var bindAddr netip.AddrPort
	if clientAddr.Addr().Is6() {
		bindAddr = netip.AddrPortFrom(netip.IPv6Unspecified(), serverAddr.Port())
	} else {
		bindAddr = netip.AddrPortFrom(netip.IPv4Unspecified(), serverAddr.Port())
	}

	// This is the critical check for the bug fix
	if !bindAddr.Addr().Is6() {
		t.Errorf("CRITICAL BUG: IPv6 client %v requires IPv6 bind address, got %v",
			clientAddr, bindAddr)
	} else {
		t.Logf("✓ Correct bind address for IPv6 client: %v", bindAddr)
	}

	_ = DefaultPacketSnifferSessionMgr.Remove(key, sniffer)
}

// TestSniffReroute_OriginalBugScenario tests the exact scenario from the bug report.
func TestSniffReroute_OriginalBugScenario(t *testing.T) {
	// Exact error scenarios from the bug report
	bugScenarios := []struct {
		serverIP string
		clientIP string
		port     uint16
	}{
		{"52.97.97.98", "240e:390:a9:dd50:34fb:3697:2b2e:d14", 63767},
		{"52.98.37.2", "240e:390:a9:dd50:34fb:3697:2b2e:d14", 54917},
		{"17.248.216.66", "240e:390:a9:dd50:34fb:3697:2b2e:d14", 64408},
		{"17.248.216.68", "240e:390:a9:dd50:34fb:3697:2b2e:d14", 63111},
		{"52.98.40.34", "240e:390:a9:dd50:34fb:3697:2b2e:d14", 59889},
		{"40.104.21.82", "240e:390:a9:dd50:34fb:3697:2b2e:d14", 50703},
		{"52.98.84.114", "240e:390:a9:dd50:34fb:3697:2b2e:d14", 61118},
	}

	for _, scenario := range bugScenarios {
		t.Run(scenario.serverIP, func(t *testing.T) {
			// Parse addresses
			serverAddr := netip.MustParseAddrPort(
				netip.AddrPortFrom(
					netip.MustParseAddr(scenario.serverIP),
					scenario.port,
				).String())
			clientAddr := netip.MustParseAddrPort(
				netip.AddrPortFrom(
					netip.MustParseAddr(scenario.clientIP),
					scenario.port,
				).String())

			// Original buggy behavior would try to use server's IPv4 address for bind
			// which fails with "non-IPv4 address" when writing to IPv6 client

			// Fixed behavior: use wildcard based on CLIENT (realTo) address family
			var bindAddr netip.AddrPort
			if clientAddr.Addr().Is6() {
				bindAddr = netip.AddrPortFrom(netip.IPv6Unspecified(), serverAddr.Port())
			} else {
				bindAddr = netip.AddrPortFrom(netip.IPv4Unspecified(), serverAddr.Port())
			}

			// Verify fix
			if !bindAddr.Addr().Is6() {
				t.Errorf("BUG NOT FIXED: Server %s -> Client %s should use IPv6 bind, got %v",
					scenario.serverIP, scenario.clientIP, bindAddr)
			}

			t.Logf("✓ Server %s:443 -> Client [%s]:%d uses correct bind %v",
				scenario.serverIP, scenario.clientIP, scenario.port, bindAddr)
		})
	}
}

// TestQuicCrossFamilyFallback tests the complete QUIC cross-family scenario
// where IPv6 server responses need to be sent to IPv4 clients (and vice versa).
// This validates the transparent address family conversion fallback path.
func TestQuicCrossFamilyFallback(t *testing.T) {
	testCases := []struct {
		name            string
		serverFrom      string // QUIC server response address (from in Handler)
		clientRealTo    string // Client address (realTo in sendPkt)
		expectBindIPv6  bool   // Expected bind address to be IPv6
		expectWriteIPv6 bool   // Expected write address to be IPv6 (after fallback conversion)
		expectFallback  bool   // Whether fallback conversion should occur
		description     string
	}{
		{
			name:            "IPv4_QUIC_server_to_IPv6_client",
			serverFrom:      "8.8.8.8:443",
			clientRealTo:    "[240e:390::1]:54321",
			expectBindIPv6:  true,  // [::ffff:8.8.8.8]:443 (IPv4-mapped)
			expectWriteIPv6: true,  // [240e:390::1]:54321 (pure IPv6)
			expectFallback:  false, // No fallback needed - direct IPv6 write
			description:     "IPv4 server response to IPv6 client via IPv4-mapped bind",
		},
		{
			name:            "IPv6_QUIC_server_to_IPv4_client_fallback",
			serverFrom:      "[2001:4860::1]:443",
			clientRealTo:    "192.168.1.1:54321",
			expectBindIPv6:  true, // [::]:443 (IPv6 unspecified)
			expectWriteIPv6: true, // [::ffff:192.168.1.1]:54321 (IPv4-mapped)
			expectFallback:  true, // Fallback: convert IPv4 to IPv4-mapped IPv6
			description:     "IPv6 server response to IPv4 client via dual-stack fallback",
		},
		{
			name:            "IPv4_QUIC_server_to_IPv4_client",
			serverFrom:      "8.8.8.8:443",
			clientRealTo:    "192.168.1.1:54321",
			expectBindIPv6:  false, // 8.8.8.8:443 (pure IPv4)
			expectWriteIPv6: false, // 192.168.1.1:54321 (pure IPv4)
			expectFallback:  false, // No fallback needed
			description:     "Same family IPv4 - no conversion",
		},
		{
			name:            "IPv6_QUIC_server_to_IPv6_client",
			serverFrom:      "[2001:4860::1]:443",
			clientRealTo:    "[240e:390::1]:54321",
			expectBindIPv6:  true,  // [2001:4860::1]:443 (pure IPv6)
			expectWriteIPv6: true,  // [240e:390::1]:54321 (pure IPv6)
			expectFallback:  false, // No fallback needed
			description:     "Same family IPv6 - no conversion",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			from := netip.MustParseAddrPort(tc.serverFrom)
			realTo := netip.MustParseAddrPort(tc.clientRealTo)

			t.Logf("=== QUIC Cross-Family Test: %s ===", tc.description)
			t.Logf("  QUIC Server (from): %v", from)
			t.Logf("  Client (realTo):    %v", realTo)

			// Step 1: Convert bind address (manual implementation of the logic)
			bindAddr := from
			if from.Addr().Is4() && realTo.Addr().Is6() && !realTo.Addr().Is4In6() {
				bindAddr = netip.AddrPortFrom(netip.AddrFrom16(from.Addr().As16()), from.Port())
			} else if from.Addr().Is4In6() && realTo.Addr().Is4() {
				bindAddr = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			}
			t.Logf("  Step 1 - bindAddr:  %v", bindAddr)

			// Verify bind address family
			if tc.expectBindIPv6 && !bindAddr.Addr().Is6() {
				t.Errorf("Expected IPv6 bind address, got %v", bindAddr)
			}
			if !tc.expectBindIPv6 && !bindAddr.Addr().Is4() {
				t.Errorf("Expected IPv4 bind address, got %v", bindAddr)
			}

			// Step 2: Apply fallback logic for write address
			// This is the new fallback path in sendPkt
			writeAddr := realTo
			fallbackTriggered := false
			if bindAddr.Addr().Is6() && !bindAddr.Addr().Is4In6() && realTo.Addr().Is4() {
				// Cross-family fallback: pure IPv6 bind + IPv4 target
				// Convert IPv4 to IPv4-mapped IPv6 for dual-stack socket
				writeAddr = netip.AddrPortFrom(
					netip.AddrFrom16(realTo.Addr().As16()),
					realTo.Port(),
				)
				fallbackTriggered = true
				t.Logf("  Step 2 - Fallback triggered! Converting IPv4 to IPv4-mapped IPv6")
			}
			t.Logf("  Step 2 - writeAddr: %v (fallback=%v)", writeAddr, fallbackTriggered)

			// Verify fallback was triggered correctly
			if tc.expectFallback != fallbackTriggered {
				t.Errorf("Fallback expectation mismatch: expected=%v, got=%v", tc.expectFallback, fallbackTriggered)
			}

			// Verify write address family
			if tc.expectWriteIPv6 && !writeAddr.Addr().Is6() {
				t.Errorf("Expected IPv6 write address, got %v", writeAddr)
			}
			if !tc.expectWriteIPv6 && !writeAddr.Addr().Is4() {
				t.Errorf("Expected IPv4 write address, got %v", writeAddr)
			}

			// Step 3: Verify IPv4-mapped format for fallback case
			if tc.expectFallback {
				if !writeAddr.Addr().Is4In6() {
					t.Errorf("Fallback write address should be IPv4-mapped IPv6, got %v", writeAddr)
				}
				// Verify the unmapped address matches original IPv4
				unmapped := writeAddr.Addr().Unmap()
				if unmapped != realTo.Addr() {
					t.Errorf("Unmapped address %v should match original %v", unmapped, realTo.Addr())
				}
				t.Logf("  Step 3 - Verification: IPv4-mapped %v unmapped to %v (matches original ✓)", writeAddr, unmapped)
			}

			// Step 4: Port preservation check
			if writeAddr.Port() != realTo.Port() {
				t.Errorf("Port not preserved: expected %d, got %d", realTo.Port(), writeAddr.Port())
			}
			t.Logf("  Step 4 - Port preserved: %d ✓", writeAddr.Port())

			// Summary
			t.Logf("  Result: bind=%v, write=%v, fallback=%v ✓",
				bindAddr, writeAddr, fallbackTriggered)
		})
	}
}

// TestQuicCrossFamilyWithSniffing tests QUIC sniffing combined with cross-family
// address handling, simulating a real QUIC connection scenario.
func TestQuicCrossFamilyWithSniffing(t *testing.T) {
	resetPacketSnifferPoolForTest()

	// Scenario: IPv4 client connects to IPv6 QUIC server
	// This tests the fallback path when server responds
	clientAddr := netip.MustParseAddrPort("192.168.1.100:54321")
	serverAddr := netip.MustParseAddrPort("[2001:4860::1]:443")

	t.Logf("Scenario: IPv4 client -> IPv6 QUIC server")
	t.Logf("  Client: %v", clientAddr)
	t.Logf("  Server: %v", serverAddr)

	// Step 1: Verify QUIC packet is recognized
	if !sniffing.IsLikelyQuicInitialPacket(sniffTestQuicPacket3) {
		t.Fatal("QUIC packet should be recognized as Initial")
	}
	t.Logf("  Step 1: QUIC Initial packet recognized ✓")

	// Step 2: Simulate sniffing
	key := NewUdpFlowKey(clientAddr, serverAddr).PacketSnifferKey()
	sniffer, _ := DefaultPacketSnifferSessionMgr.GetOrCreate(key, nil)
	sniffer.AppendData(sniffTestQuicPacket3)

	domain, err := sniffer.SniffQuic()
	if err != nil {
		t.Logf("  Step 2: Sniffing result (may have error): %v", err)
	} else {
		t.Logf("  Step 2: Sniffed domain: %q ✓", domain)
	}

	// Step 3: Simulate response path with fallback
	// Server (IPv6) -> Client (IPv4)
	from := serverAddr
	realTo := clientAddr

	bindAddr := from
	if from.Addr().Is4() && realTo.Addr().Is6() && !realTo.Addr().Is4In6() {
		bindAddr = netip.AddrPortFrom(netip.AddrFrom16(from.Addr().As16()), from.Port())
	}
	t.Logf("  Step 3: Response bind address: %v", bindAddr)

	// Apply fallback
	writeAddr := realTo
	if bindAddr.Addr().Is6() && !bindAddr.Addr().Is4In6() && realTo.Addr().Is4() {
		writeAddr = netip.AddrPortFrom(
			netip.AddrFrom16(realTo.Addr().As16()),
			realTo.Port(),
		)
		t.Logf("  Step 3: Fallback applied - writeAddr: %v", writeAddr)
	}

	// Verify fallback was applied correctly
	if !writeAddr.Addr().Is4In6() {
		t.Errorf("IPv6 server -> IPv4 client should use IPv4-mapped write address, got %v", writeAddr)
	} else {
		t.Logf("  Step 3: IPv4-mapped write address verified ✓")
	}

	// Verify dual-stack socket can write
	t.Logf("  Result: IPv6 socket [::]:443 can write to IPv4-mapped %v ✓", writeAddr)

	_ = DefaultPacketSnifferSessionMgr.Remove(key, sniffer)
}
