package netutils

import (
	"net/netip"
	"sync"
	"testing"
)

func TestSystemDNSResolverIsGenerationScoped(t *testing.T) {
	fallbackA := netip.MustParseAddrPort("1.1.1.1:53")
	fallbackB := netip.MustParseAddrPort("8.8.8.8:53")
	localOnly := func(string) *dnsConfig {
		return &dnsConfig{servers: []string{"127.0.0.1:53", "[::1]:53"}}
	}

	resolverA := NewSystemDNSResolver(fallbackA)
	resolverA.readConfig = localOnly
	resolverB := NewSystemDNSResolver(fallbackB)
	resolverB.readConfig = localOnly

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			got, err := resolverA.SystemDNS()
			if err != nil {
				t.Errorf("resolver A: %v", err)
				return
			}
			if got != fallbackA {
				t.Errorf("resolver A = %v, want %v", got, fallbackA)
			}
		}()
		go func() {
			defer wg.Done()
			got, err := resolverB.SystemDNS()
			if err != nil {
				t.Errorf("resolver B: %v", err)
				return
			}
			if got != fallbackB {
				t.Errorf("resolver B = %v, want %v", got, fallbackB)
			}
		}()
	}
	wg.Wait()
}
