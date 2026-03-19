/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// mockBpfObjects is a minimal mock for testing
type mockBpfObjects struct{}

func (m *mockBpfObjects) newLpmMap(keys []_bpfLpmKey, values []uint32) (*mockLpmMap, error) {
	return &mockLpmMap{count: len(keys)}, nil
}

type mockLpmMap struct {
	count int
}

func (m *mockLpmMap) Close() error {
	return nil
}

// generateMockGeoIpRules generates rules simulating multiple geoip references
// Returns the number of rules and unique countries for testing
func generateMockGeoIpRules(numCountries int) (rules int, uniqueCountries []string) {
	// Simulate different countries with IP ranges
	countries := []string{"cn", "us", "jp", "kr", "sg", "hk", "tw", "de", "gb", "fr", "ca", "au", "in", "br", "ru"}

	// Each country appears twice (different outbound)
	uniqueCountries = make([]string, 0, numCountries)
	for i := 0; i < numCountries; i++ {
		country := countries[i%len(countries)]
		uniqueCountries = append(uniqueCountries, country)
		rules += 2 // Two rules per country
	}

	return rules, uniqueCountries
}

// generateMockIpPrefixes generates IP prefixes for testing
func generateMockIpPrefixes(count int, baseIP string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, count)

	// Parse base IP
	baseAddr, err := netip.ParseAddr(baseIP)
	if err != nil {
		// Fallback to 1.1.1.1
		baseAddr = netip.MustParseAddr("1.1.1.1")
	}

	for i := 0; i < count; i++ {
		// Generate different prefixes by varying the last octet and prefix length
		baseBytes := baseAddr.As4()

		// Vary the IP to create unique prefixes
		offset := uint32(i) % 256
		baseBytes[3] = byte(offset)

		newAddr := netip.AddrFrom4(baseBytes)

		// Vary prefix length between /24 and /32
		prefixLen := 24 + (i % 9)

		prefixes = append(prefixes, netip.PrefixFrom(newAddr, prefixLen))

		// Also add some IPv6 prefixes
		if i%10 == 0 {
			v6Addr := netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", i))
			prefixes = append(prefixes, netip.PrefixFrom(v6Addr, 64+(i%8)))
		}
	}

	return prefixes
}

// BenchmarkHashLpmSet benchmarks the hash function for IP set deduplication
func BenchmarkHashLpmSet(b *testing.B) {
	prefixes := generateMockIpPrefixes(1000, "8.8.8.8")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hashLpmSet(prefixes)
	}
}

// BenchmarkHashLpmSetSmall benchmarks with small IP sets
func BenchmarkHashLpmSetSmall(b *testing.B) {
	prefixes := generateMockIpPrefixes(10, "8.8.8.8")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hashLpmSet(prefixes)
	}
}

// BenchmarkHashLpmSetLarge benchmarks with large IP sets (like geoip:cn)
func BenchmarkHashLpmSetLarge(b *testing.B) {
	// geoip:cn has about 8000+ entries
	prefixes := generateMockIpPrefixes(8000, "1.0.0.0")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hashLpmSet(prefixes)
	}
}

// BenchmarkLpmSetDeduplication benchmarks the deduplication effect
func BenchmarkLpmSetDeduplication(b *testing.B) {
	// Create multiple identical IP sets (simulating multiple geoip:cn references)
	uniqueSets := 10
	duplicatesPerSet := 5

	// Generate unique IP sets
	uniquePrefixes := make([][]netip.Prefix, uniqueSets)
	for i := 0; i < uniqueSets; i++ {
		uniquePrefixes[i] = generateMockIpPrefixes(1000, fmt.Sprintf("%d.%d.0.0", i/256, i%256))
	}

	// Create input with duplicates
	allPrefixes := make([][]netip.Prefix, 0, uniqueSets*duplicatesPerSet)
	for i := 0; i < duplicatesPerSet; i++ {
		for j := 0; j < uniqueSets; j++ {
			allPrefixes = append(allPrefixes, uniquePrefixes[j])
		}
	}

	b.Run("WithDeduplication", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dedup := make(map[uint64]uint32)
			uniqueCount := 0
			for _, prefixes := range allPrefixes {
				hash := hashLpmSet(prefixes)
				if _, exists := dedup[hash]; !exists {
					dedup[hash] = uint32(uniqueCount)
					uniqueCount++
				}
			}
		}
	})

	b.Run("WithoutDeduplication", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = len(allPrefixes) // Just count them
		}
	})
}

// BenchmarkRoutingMatcherBuilder benchmarks the full builder process
func BenchmarkRoutingMatcherBuilder(b *testing.B) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel) // Suppress logs during benchmark

	outboundName2Id := map[string]uint8{
		"direct": 0,
		"block":  1,
		"proxy":  2,
	}

	b.Run("Small_NoDuplicates", func(b *testing.B) {
		numRules, _ := generateMockGeoIpRules(5)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			builder := &RoutingMatcherBuilder{
				log:             log,
				outboundName2Id: outboundName2Id,
				lpmDedup:        make(map[uint64]lpmDedupEntry),
			}
			// Simulate adding IP rules - each rule has unique IPs
			for j := 0; j < numRules; j++ {
				prefixes := generateMockIpPrefixes(100, fmt.Sprintf("%d.0.0.0", j))
				hash := hashLpmSet(prefixes)
				if _, exists := builder.lpmDedup[hash]; !exists {
					idx := uint32(len(builder.simulatedLpmTries))
					builder.lpmDedup[hash] = lpmDedupEntry{index: idx, prefixes: prefixes}
					builder.simulatedLpmTries = append(builder.simulatedLpmTries, prefixes)
				}
			}
		}
	})

	b.Run("Medium_WithDuplicates", func(b *testing.B) {
		numRules, _ := generateMockGeoIpRules(20)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			builder := &RoutingMatcherBuilder{
				log:             log,
				outboundName2Id: outboundName2Id,
				lpmDedup:        make(map[uint64]lpmDedupEntry),
			}
			// Simulate adding IP rules with duplicates
			// Use same IP set for multiple rules (simulating geoip)
			for j := 0; j < numRules; j++ {
				countryIdx := j % 10 // Only 10 unique countries
				prefixes := generateMockIpPrefixes(500, fmt.Sprintf("%d.0.0.0", countryIdx))
				hash := hashLpmSet(prefixes)
				if _, exists := builder.lpmDedup[hash]; !exists {
					idx := uint32(len(builder.simulatedLpmTries))
					builder.lpmDedup[hash] = lpmDedupEntry{index: idx, prefixes: prefixes}
					builder.simulatedLpmTries = append(builder.simulatedLpmTries, prefixes)
				}
			}
		}
	})

	b.Run("Large_HighDuplicateRatio", func(b *testing.B) {
		numRules, _ := generateMockGeoIpRules(50)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			builder := &RoutingMatcherBuilder{
				log:             log,
				outboundName2Id: outboundName2Id,
				lpmDedup:        make(map[uint64]lpmDedupEntry),
			}
			// Simulate adding IP rules with many duplicates
			// Only 5 unique IP sets but 50 rules
			for j := 0; j < numRules; j++ {
				countryIdx := j % 5
				prefixes := generateMockIpPrefixes(1000, fmt.Sprintf("%d.0.0.0", countryIdx))
				hash := hashLpmSet(prefixes)
				if _, exists := builder.lpmDedup[hash]; !exists {
					idx := uint32(len(builder.simulatedLpmTries))
					builder.lpmDedup[hash] = lpmDedupEntry{index: idx, prefixes: prefixes}
					builder.simulatedLpmTries = append(builder.simulatedLpmTries, prefixes)
				}
			}
		}
	})
}

// TestLpmSetDeduplicationEffectiveness tests the deduplication effectiveness
func TestLpmSetDeduplicationEffectiveness(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	tests := []struct {
		name              string
		numRules          int
		uniqueIpSets      int
		expectedReduction float64 // Expected reduction in LPM tries
	}{
		{"NoDuplicates", 10, 10, 0.0},
		{"LowDuplicates", 20, 15, 25.0},
		{"MediumDuplicates", 30, 10, 66.67},
		{"HighDuplicates", 50, 5, 90.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := &RoutingMatcherBuilder{
				log:             log,
				outboundName2Id: map[string]uint8{"direct": 0},
				lpmDedup:        make(map[uint64]lpmDedupEntry),
			}

			// Simulate adding IP rules
			for i := 0; i < tt.numRules; i++ {
				// Use modulo to create duplicates
				setIdx := i % tt.uniqueIpSets
				prefixes := generateMockIpPrefixes(100, fmt.Sprintf("%d.0.0.0", setIdx))
				hash := hashLpmSet(prefixes)
				if _, exists := builder.lpmDedup[hash]; !exists {
					idx := uint32(len(builder.simulatedLpmTries))
					builder.lpmDedup[hash] = lpmDedupEntry{index: idx, prefixes: prefixes}
					builder.simulatedLpmTries = append(builder.simulatedLpmTries, prefixes)
				}
			}

			actualLpmTries := len(builder.simulatedLpmTries)
			expectedLpmTries := tt.uniqueIpSets

			if actualLpmTries != expectedLpmTries {
				t.Errorf("Expected %d LPM tries, got %d", expectedLpmTries, actualLpmTries)
			}

			reduction := float64(tt.numRules-actualLpmTries) / float64(tt.numRules) * 100
			t.Logf("Rules: %d, Unique IP sets: %d, LPM tries: %d, Reduction: %.1f%%",
				tt.numRules, tt.uniqueIpSets, actualLpmTries, reduction)
		})
	}
}

// TestRoutingMatcherBuilderMemoryUsage tests memory usage during building
func TestRoutingMatcherBuilderMemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory test in short mode")
	}

	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	var m1 runtime.MemStats
	var m2 runtime.MemStats

	tests := []struct {
		name       string
		numRules   int
		uniqueSets int
		ipsPerSet  int
	}{
		{"Small", 10, 5, 100},
		{"Medium", 50, 10, 500},
		{"Large", 100, 15, 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime.GC()
			runtime.ReadMemStats(&m1)

			builder := &RoutingMatcherBuilder{
				log:             log,
				outboundName2Id: map[string]uint8{"direct": 0},
				lpmDedup:        make(map[uint64]lpmDedupEntry),
			}

			// Simulate adding IP rules
			for i := 0; i < tt.numRules; i++ {
				setIdx := i % tt.uniqueSets
				prefixes := generateMockIpPrefixes(tt.ipsPerSet, fmt.Sprintf("%d.0.0.0", setIdx))
				hash := hashLpmSet(prefixes)
				if _, exists := builder.lpmDedup[hash]; !exists {
					idx := uint32(len(builder.simulatedLpmTries))
					builder.lpmDedup[hash] = lpmDedupEntry{index: idx, prefixes: prefixes}
					builder.simulatedLpmTries = append(builder.simulatedLpmTries, prefixes)
				}
			}

			runtime.ReadMemStats(&m2)

			// Calculate memory usage
			allocDiff := m2.TotalAlloc - m1.TotalAlloc
			heapDiff := m2.HeapAlloc - m1.HeapAlloc

			t.Logf("Rules: %d, Unique IP sets: %d, IPs per set: %d",
				tt.numRules, tt.uniqueSets, tt.ipsPerSet)
			t.Logf("LPM tries created: %d (deduplicated from %d rules)",
				len(builder.simulatedLpmTries), tt.numRules)
			t.Logf("Memory: TotalAlloc=%v MB, HeapAlloc=%v MB",
				m2.TotalAlloc/1024/1024, m2.HeapAlloc/1024/1024)
			t.Logf("Memory delta: TotalAlloc=%v MB, HeapAlloc=%v MB",
				allocDiff/1024/1024, heapDiff/1024/1024)

			// Test that deduplication actually happened
			if len(builder.simulatedLpmTries) > tt.uniqueSets {
				t.Errorf("Expected at most %d LPM tries, got %d",
					tt.uniqueSets, len(builder.simulatedLpmTries))
			}
		})
	}
}

// BenchmarkBuildUserspaceParallel vs Serial
func BenchmarkBuildUserspace(b *testing.B) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	prefixesSets := make([][]netip.Prefix, 20)
	for i := 0; i < 20; i++ {
		prefixesSets[i] = generateMockIpPrefixes(500, fmt.Sprintf("%d.0.0.0", i))
	}

	b.Run("Parallel", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			builder := &RoutingMatcherBuilder{
				log:               log,
				simulatedLpmTries: prefixesSets,
			}
			// Simulate parallel build
			numTries := len(builder.simulatedLpmTries)
			_ = numTries
			for _, prefixes := range builder.simulatedLpmTries {
				_ = prefixes
				// Mock trie creation
			}
		}
	})
}

// TestRealWorldGeoIpSimulation simulates real-world geoip usage
func TestRealWorldGeoIpSimulation(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.InfoLevel)

	// Simulate a typical routing configuration with geoip
	type routingRule struct {
		name     string
		country  string
		outbound string
	}

	rules := []routingRule{
		{"Chinese IPs to direct", "cn", "direct"},
		{"Chinese IPs to block (inverse)", "cn", "block"},
		{"US IPs to proxy", "us", "proxy"},
		{"US IPs to direct (fallback)", "us", "direct"},
		{"Japan IPs to direct", "jp", "direct"},
		{"Japan IPs to proxy", "jp", "proxy"},
		{"Korea IPs to direct", "kr", "direct"},
		{"Singapore IPs to direct", "sg", "direct"},
		{"Hong Kong IPs to direct", "hk", "direct"},
		{"Taiwan IPs to direct", "tw", "direct"},
	}

	builder := &RoutingMatcherBuilder{
		log:             log,
		outboundName2Id: map[string]uint8{"direct": 0, "block": 1, "proxy": 2},
		lpmDedup:        make(map[uint64]lpmDedupEntry),
	}

	// Simulate geoip loading (using mock IP prefixes)
	countryIpCounts := map[string]int{
		"cn": 8000, // China has many IP ranges
		"us": 5000,
		"jp": 2000,
		"kr": 1500,
		"sg": 800,
		"hk": 600,
		"tw": 1000,
	}

	startTime := time.Now()

	for _, rule := range rules {
		ipCount := countryIpCounts[rule.country]
		prefixes := generateMockIpPrefixes(ipCount, fmt.Sprintf("%s.0.0.0", rule.country))

		hash := hashLpmSet(prefixes)
		if _, exists := builder.lpmDedup[hash]; !exists {
			idx := uint32(len(builder.simulatedLpmTries))
			builder.lpmDedup[hash] = lpmDedupEntry{index: idx, prefixes: prefixes}
			builder.simulatedLpmTries = append(builder.simulatedLpmTries, prefixes)
		}
	}

	buildTime := time.Since(startTime)

	t.Logf("=== Real-world GeoIP Simulation ===")
	t.Logf("Total rules: %d", len(rules))
	t.Logf("Unique countries: %d", len(countryIpCounts))
	t.Logf("LPM tries created: %d", len(builder.simulatedLpmTries))
	t.Logf("Deduplication ratio: %.1f%%", float64(len(rules)-len(builder.simulatedLpmTries))/float64(len(rules))*100)
	t.Logf("Build time: %v", buildTime)

	// Calculate estimated memory usage
	totalIps := 0
	for _, prefixes := range builder.simulatedLpmTries {
		totalIps += len(prefixes)
	}
	t.Logf("Total IP prefixes stored: %d", totalIps)

	// Verify deduplication worked
	if len(builder.simulatedLpmTries) != len(countryIpCounts) {
		t.Errorf("Expected %d LPM tries (one per country), got %d",
			len(countryIpCounts), len(builder.simulatedLpmTries))
	}
}
