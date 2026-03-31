package direct

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

type lookupIPAddrCapable interface {
	LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error)
}

func TestDirectDialersExposeLookupIPAddr(t *testing.T) {
	if _, ok := SymmetricDirect.(lookupIPAddrCapable); !ok {
		t.Fatalf("SymmetricDirect does not expose LookupIPAddr")
	}
	if _, ok := FullconeDirect.(lookupIPAddrCapable); !ok {
		t.Fatalf("FullconeDirect does not expose LookupIPAddr")
	}

	dialer := NewDirectDialerLaddr(netip.Addr{}, Option{})
	if _, ok := dialer.(lookupIPAddrCapable); !ok {
		t.Fatalf("NewDirectDialerLaddr() result does not expose LookupIPAddr")
	}
}
