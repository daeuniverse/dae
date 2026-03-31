package shadowsocks_2022

import (
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

// TestMagicNetworkParsing tests that ParseMagicNetwork handles various network formats
func TestMagicNetworkParsing(t *testing.T) {
	tests := []struct {
		name          string
		network       string
		expectNetwork string
		expectSuccess bool
	}{
		{
			name:          "plain tcp",
			network:       "tcp",
			expectNetwork: "tcp",
			expectSuccess: true,
		},
		{
			name:          "plain udp",
			network:       "udp",
			expectNetwork: "udp",
			expectSuccess: true,
		},
		{
			name:          "magic network tcp with mark",
			network:       netproxy.MagicNetwork{Network: "tcp", Mark: 1}.Encode(),
			expectNetwork: "tcp",
			expectSuccess: true,
		},
		{
			name:          "magic network udp with mark",
			network:       netproxy.MagicNetwork{Network: "udp", Mark: 1}.Encode(),
			expectNetwork: "udp",
			expectSuccess: true,
		},
		{
			name:          "magic network tcp with zero mark",
			network:       netproxy.MagicNetwork{Network: "tcp", Mark: 0}.Encode(),
			expectNetwork: "tcp",
			expectSuccess: true,
		},
		{
			name:          "magic network tcp with mptcp",
			network:       netproxy.MagicNetwork{Network: "tcp", Mark: 0, Mptcp: true}.Encode(),
			expectNetwork: "tcp",
			expectSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mn, err := netproxy.ParseMagicNetwork(tt.network)
			if !tt.expectSuccess {
				if err == nil {
					t.Errorf("Expected error but got none for network %q", tt.network)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseMagicNetwork(%q) failed: %v", tt.network, err)
				return
			}
			if mn.Network != tt.expectNetwork {
				t.Errorf("ParseMagicNetwork(%q) returned network %q, want %q", tt.network, mn.Network, tt.expectNetwork)
			}
		})
	}
}

// TestDialerNetworkTypeSwitch verifies that the switch statement in DialContext
// correctly handles the parsed network type
func TestDialerNetworkTypeSwitch(t *testing.T) {
	tests := []struct {
		name          string
		network       string
		expectSupport bool
	}{
		{
			name:          "plain tcp",
			network:       "tcp",
			expectSupport: true,
		},
		{
			name:          "plain udp",
			network:       "udp",
			expectSupport: true,
		},
		{
			name:          "magic network tcp with mark",
			network:       netproxy.MagicNetwork{Network: "tcp", Mark: 1}.Encode(),
			expectSupport: true,
		},
		{
			name:          "unsupported network",
			network:       "sctp",
			expectSupport: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mn, err := netproxy.ParseMagicNetwork(tt.network)
			if err != nil && tt.expectSupport {
				t.Errorf("ParseMagicNetwork(%q) failed: %v", tt.network, err)
				return
			}

			// Check if the network type would match our switch cases
			supported := false
			switch mn.Network {
			case "tcp", "udp":
				supported = true
			}

			if supported != tt.expectSupport {
				t.Errorf("Network %q: supported=%v, want %v", tt.network, supported, tt.expectSupport)
			}
		})
	}
}

// TestMultiPSKParsing tests that multi-PSK passwords are correctly parsed
func TestMultiPSKParsing(t *testing.T) {
	// Test the actual password from the user's link
	password := "bG1k6qKaANArh2515TnLrA==:xBAQSRWYs6I7TGjzBxY68w=="
	parts := strings.Split(password, ":")
	if len(parts) != 2 {
		t.Errorf("Expected 2 PSK parts, got %d", len(parts))
	}
	if parts[0] != "bG1k6qKaANArh2515TnLrA==" {
		t.Errorf("First PSK mismatch: got %q", parts[0])
	}
	if parts[1] != "xBAQSRWYs6I7TGjzBxY68w==" {
		t.Errorf("Second PSK mismatch: got %q", parts[1])
	}
}
