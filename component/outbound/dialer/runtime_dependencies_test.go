package dialer

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/netproxy"
)

type runtimeDependencyDialer struct{ id int }

func (*runtimeDependencyDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, nil
}

type runtimeDependencyDNS struct{}

func (runtimeDependencyDNS) SystemDNS() (netip.AddrPort, error) {
	return netip.MustParseAddrPort("1.1.1.1:53"), nil
}

func (runtimeDependencyDNS) TryUpdateElapse(time.Duration) error { return nil }

func TestGlobalOptionRuntimeDependenciesStayTogether(t *testing.T) {
	option := NewGlobalOption(&config.Global{}, nil)
	symmetric := &runtimeDependencyDialer{id: 1}
	fullcone := &runtimeDependencyDialer{id: 2}
	resolver := runtimeDependencyDNS{}

	option.SetRuntimeDependencies(symmetric, fullcone, resolver)

	if option.DirectDialer != symmetric || option.FullconeDirectDialer != fullcone {
		t.Fatal("direct dialers were not installed")
	}
	if option.SystemDNSResolver != resolver {
		t.Fatal("system DNS resolver was not installed")
	}
	if option.TcpCheckOptionRaw.DirectDialer != symmetric || option.TcpCheckOptionRaw.SystemDNSResolver != resolver {
		t.Fatal("TCP check dependencies diverged from the generation")
	}
	if option.CheckDnsOptionRaw.DirectDialer != symmetric || option.CheckDnsOptionRaw.SystemDNSResolver != resolver {
		t.Fatal("DNS check dependencies diverged from the generation")
	}
}
