package dialer

import (
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/netproxy"
)

func TestNewGlobalOptionUsesEffectiveSoMarkFromDaeWhenUnset(t *testing.T) {
	option := NewGlobalOption(&config.Global{}, nil)
	if option.SoMarkFromDae != common.InternalSoMarkFromDae {
		t.Fatalf("SoMarkFromDae = %#x, want %#x", option.SoMarkFromDae, common.InternalSoMarkFromDae)
	}
	if option.CheckDnsOptionRaw.Somark != common.InternalSoMarkFromDae {
		t.Fatalf("CheckDnsOptionRaw.Somark = %#x, want %#x", option.CheckDnsOptionRaw.Somark, common.InternalSoMarkFromDae)
	}

	magicNetwork, err := netproxy.ParseMagicNetwork(option.TcpCheckOptionRaw.ResolverNetwork)
	if err != nil {
		t.Fatalf("ParseMagicNetwork(tcp resolver) error = %v", err)
	}
	if magicNetwork.Mark != common.InternalSoMarkFromDae {
		t.Fatalf("tcp resolver mark = %#x, want %#x", magicNetwork.Mark, common.InternalSoMarkFromDae)
	}

	magicNetwork, err = netproxy.ParseMagicNetwork(option.CheckDnsOptionRaw.ResolverNetwork)
	if err != nil {
		t.Fatalf("ParseMagicNetwork(dns resolver) error = %v", err)
	}
	if magicNetwork.Mark != common.InternalSoMarkFromDae {
		t.Fatalf("dns resolver mark = %#x, want %#x", magicNetwork.Mark, common.InternalSoMarkFromDae)
	}
	if option.TransportCacheNamespace == "" {
		t.Fatal("expected transport cache namespace to be initialized")
	}
}

func TestNewGlobalOptionPreservesConfiguredSoMarkFromDae(t *testing.T) {
	const configured uint32 = 0x3023
	option := NewGlobalOption(&config.Global{SoMarkFromDae: configured}, nil)
	if option.SoMarkFromDae != configured {
		t.Fatalf("SoMarkFromDae = %#x, want %#x", option.SoMarkFromDae, configured)
	}
}

func TestNewGlobalOptionCreatesUniqueTransportCacheNamespace(t *testing.T) {
	first := NewGlobalOption(&config.Global{}, nil)
	second := NewGlobalOption(&config.Global{}, nil)
	if first.TransportCacheNamespace == second.TransportCacheNamespace {
		t.Fatalf("transport cache namespace collision: %q", first.TransportCacheNamespace)
	}
}
