package netutils

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol/direct"
)

func TestResolveIp46(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ip46, err := ResolveIp46(ctx, direct.SymmetricDirect, netip.MustParseAddrPort("223.5.5.5:53"), "www.apple.com", "udp", false)
	if err != nil {
		t.Fatal(err)
	}
	if !ip46.Ip4.IsValid() && !ip46.Ip6.IsValid() {
		t.Fatal("No record")
	}
}
