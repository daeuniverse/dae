package dialer

import (
	"context"
	"net"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

type recordingNetworkDialer struct {
	dialNetwork   string
	dialAddr      string
	lookupNetwork string
	lookupHost    string
}

func (d *recordingNetworkDialer) DialContext(_ context.Context, network, addr string) (netproxy.Conn, error) {
	d.dialNetwork = network
	d.dialAddr = addr
	return nil, nil
}

func (d *recordingNetworkDialer) LookupIPAddr(_ context.Context, network, host string) ([]net.IPAddr, error) {
	d.lookupNetwork = network
	d.lookupHost = host
	return nil, nil
}

func TestDefaultNetworkDialerAddsDefaultsToPlainNetwork(t *testing.T) {
	parent := &recordingNetworkDialer{}
	dialer := newDefaultNetworkDialer(parent, 123, true)

	if _, err := dialer.DialContext(context.Background(), "udp", "proxy.example:443"); err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if got, want := parent.dialAddr, "proxy.example:443"; got != want {
		t.Fatalf("dial addr = %q, want %q", got, want)
	}

	magicNetwork, err := netproxy.ParseMagicNetwork(parent.dialNetwork)
	if err != nil {
		t.Fatalf("ParseMagicNetwork() error = %v", err)
	}
	if got, want := magicNetwork.Network, "udp"; got != want {
		t.Fatalf("network = %q, want %q", got, want)
	}
	if got, want := magicNetwork.Mark, uint32(123); got != want {
		t.Fatalf("mark = %d, want %d", got, want)
	}
	if !magicNetwork.Mptcp {
		t.Fatal("mptcp = false, want true")
	}
}

func TestDefaultNetworkDialerMergesExistingMagicNetwork(t *testing.T) {
	parent := &recordingNetworkDialer{}
	dialer := newDefaultNetworkDialer(parent, 123, true)
	network := netproxy.MagicNetwork{Network: "tcp", Mark: 7, IPVersion: "6"}.Encode()

	if _, err := dialer.DialContext(context.Background(), network, "proxy.example:443"); err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}

	magicNetwork, err := netproxy.ParseMagicNetwork(parent.dialNetwork)
	if err != nil {
		t.Fatalf("ParseMagicNetwork() error = %v", err)
	}
	if got, want := magicNetwork.Network, "tcp"; got != want {
		t.Fatalf("network = %q, want %q", got, want)
	}
	if got, want := magicNetwork.Mark, uint32(7); got != want {
		t.Fatalf("mark = %d, want %d", got, want)
	}
	if !magicNetwork.Mptcp {
		t.Fatal("mptcp = false, want true")
	}
	if got, want := magicNetwork.IPVersion, "6"; got != want {
		t.Fatalf("ip version = %q, want %q", got, want)
	}
}

func TestDefaultNetworkDialerForwardsLookupWithMergedNetwork(t *testing.T) {
	parent := &recordingNetworkDialer{}
	dialer := newDefaultNetworkDialer(parent, 456, false).(*defaultNetworkDialer)

	if _, err := dialer.LookupIPAddr(context.Background(), "tcp", "proxy.example"); err != nil {
		t.Fatalf("LookupIPAddr() error = %v", err)
	}
	if got, want := parent.lookupHost, "proxy.example"; got != want {
		t.Fatalf("lookup host = %q, want %q", got, want)
	}

	magicNetwork, err := netproxy.ParseMagicNetwork(parent.lookupNetwork)
	if err != nil {
		t.Fatalf("ParseMagicNetwork() error = %v", err)
	}
	if got, want := magicNetwork.Network, "tcp"; got != want {
		t.Fatalf("network = %q, want %q", got, want)
	}
	if got, want := magicNetwork.Mark, uint32(456); got != want {
		t.Fatalf("mark = %d, want %d", got, want)
	}
	if magicNetwork.Mptcp {
		t.Fatal("mptcp = true, want false")
	}
}
