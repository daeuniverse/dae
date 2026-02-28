/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org
 *
 * Race condition tests for IPv4/IPv6 address family conversion
 *
 * These tests verify that ConvertAddrPortForTarget is thread-safe
 * under concurrent access.
 */

package common

import (
	"net/netip"
	"sync"
	"testing"
)

// TestConvertAddrPortForTarget_Concurrent tests concurrent access to ConvertAddrPortForTarget
func TestConvertAddrPortForTarget_Concurrent(t *testing.T) {
	testCases := []struct {
		source string
		target string
	}{
		{"192.168.1.1:443", "8.8.8.8:53"},
		{"8.8.8.8:53", "[::1]:12345"},
		{"[::1]:12345", "192.168.1.1:443"},
		{"[2001:4860::1]:443", "[240e:390::1]:53"},
		{"40.99.181.130:443", "[240e:390:a9:dd50:34fb:3697:2b2e:d14]:52215"},
		{"[::ffff:192.168.1.1]:443", "192.168.1.2:53"},
	}

	const numGoroutines = 100
	const numOperations = 1000

	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				tc := testCases[j%len(testCases)]
				source := netip.MustParseAddrPort(tc.source)
				target := netip.MustParseAddrPort(tc.target)
				result := ConvertAddrPortForTarget(source, target)
				// Use the result to prevent optimization
				if result.Port() == 0 && id == 0 && j == 0 {
					t.Errorf("Unexpected zero port")
				}
			}
		}(i)
	}
	wg.Wait()
}

// TestConvertAddrPortForTarget_ConcurrentSameInput tests concurrent access with identical inputs
func TestConvertAddrPortForTarget_ConcurrentSameInput(t *testing.T) {
	// All goroutines use the same input to maximize contention
	source := netip.MustParseAddrPort("40.99.181.130:443")
	target := netip.MustParseAddrPort("[240e:390:a9:dd50:34fb:3697:2b2e:d14]:52215")

	const numGoroutines = 1000
	var wg sync.WaitGroup

	results := make([]netip.AddrPort, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			results[id] = ConvertAddrPortForTarget(source, target)
		}(i)
	}
	wg.Wait()

	// All results should be identical
	expected := ConvertAddrPortForTarget(source, target)
	for i, r := range results {
		if r != expected {
			t.Errorf("Goroutine %d: expected %v, got %v", i, expected, r)
		}
	}
}

// TestConvertAddrPortForTarget_ConcurrentMixed tests mixed scenarios with both conversions
func TestConvertAddrPortForTarget_ConcurrentMixed(t *testing.T) {
	ipv4Source := netip.MustParseAddrPort("192.168.1.1:443")
	ipv6Source := netip.MustParseAddrPort("[2001:4860::1]:443")
	ipv4Target := netip.MustParseAddrPort("8.8.8.8:53")
	ipv6Target := netip.MustParseAddrPort("[::1]:12345")

	const numGoroutines = 50
	const numOperations = 200

	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				var source, target netip.AddrPort
				switch j % 4 {
				case 0:
					source, target = ipv4Source, ipv4Target
				case 1:
					source, target = ipv4Source, ipv6Target
				case 2:
					source, target = ipv6Source, ipv4Target
				case 3:
					source, target = ipv6Source, ipv6Target
				}
				_ = ConvertAddrPortForTarget(source, target)
			}
		}(i)
	}
	wg.Wait()
}

// BenchmarkConvertAddrPortForTarget_Concurrent benchmarks concurrent access
func BenchmarkConvertAddrPortForTarget_Concurrent(b *testing.B) {
	source := netip.MustParseAddrPort("40.99.181.130:443")
	target := netip.MustParseAddrPort("[240e:390:a9:dd50:34fb:3697:2b2e:d14]:52215")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = ConvertAddrPortForTarget(source, target)
		}
	})
}
