/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/sirupsen/logrus"
)

func mustParsePrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

func TestPrefixCompressor_RemoveDuplicates(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	compressor := NewPrefixCompressor(log)

	prefixes := []netip.Prefix{
		mustParsePrefix("192.168.1.0/24"),
		mustParsePrefix("192.168.1.0/24"), // Duplicate
		mustParsePrefix("10.0.0.0/8"),
		mustParsePrefix("10.0.0.0/8"), // Duplicate
		mustParsePrefix("172.16.0.0/12"),
	}

	compressed, original, removed := compressor.Compress(prefixes)

	if len(compressed) != 3 {
		t.Errorf("Expected 3 unique prefixes, got %d", len(compressed))
	}
	if original != 5 {
		t.Errorf("Expected original count 5, got %d", original)
	}
	if removed != 2 {
		t.Errorf("Expected removed count 2, got %d", removed)
	}
}

func TestPrefixCompressor_RemoveRedundant(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	compressor := NewPrefixCompressor(log)

	// 10.0.0.0/8 covers all other 10.x.x.x addresses
	prefixes := []netip.Prefix{
		mustParsePrefix("10.0.0.0/8"),
		mustParsePrefix("10.1.2.3/32"),    // Redundant
		mustParsePrefix("10.255.0.0/16"),  // Redundant
		mustParsePrefix("192.168.1.0/24"), // Not redundant
		mustParsePrefix("172.16.0.0/12"),
	}

	compressed, _, removed := compressor.Compress(prefixes)

	// Should remove 2 redundant entries
	if removed != 2 {
		t.Errorf("Expected 2 removed entries, got %d", removed)
	}

	// Check that specific entries were removed
	hasBroad10 := false
	for _, p := range compressed {
		if p.String() == "10.0.0.0/8" {
			hasBroad10 = true
		}
		if p.String() == "10.1.2.3/32" {
			t.Errorf("Redundant 10.1.2.3/32 should have been removed")
		}
		if p.String() == "10.255.0.0/16" {
			t.Errorf("Redundant 10.255.0.0/16 should have been removed")
		}
	}

	if !hasBroad10 {
		t.Errorf("Broad 10.0.0.0/8 should be present")
	}
}

func TestPrefixCompressor_RealWorld(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.InfoLevel)
	compressor := NewPrefixCompressor(log)

	// Simulate geoip data with some redundancy
	prefixes := make([]netip.Prefix, 0, 100)

	// Add overlapping ranges (broad first)
	prefixes = append(prefixes, mustParsePrefix("1.0.0.0/8"))
	// These are redundant
	prefixes = append(prefixes, mustParsePrefix("1.0.1.0/24"))
	prefixes = append(prefixes, mustParsePrefix("1.1.0.0/16"))
	prefixes = append(prefixes, mustParsePrefix("1.255.0.0/16"))

	// Add some unrelated ranges
	for i := 0; i < 10; i++ {
		prefixes = append(prefixes, mustParsePrefix(fmt.Sprintf("14.0.%d.0/24", i)))
	}

	// Add duplicates
	prefixes = append(prefixes, mustParsePrefix("14.0.0.0/24"))
	prefixes = append(prefixes, mustParsePrefix("14.0.0.0/24"))

	originalCount := len(prefixes)
	t.Logf("Original: %d prefixes", originalCount)

	compressed, _, removed := compressor.Compress(prefixes)

	t.Logf("Compressed: %d prefixes", len(compressed))
	t.Logf("Removed: %d prefixes (%.1f%% reduction)",
		removed, float64(removed)/float64(originalCount)*100)

	if removed == 0 {
		t.Error("Expected some compression, but none occurred")
	}
}

func BenchmarkPrefixCompressor(b *testing.B) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	compressor := NewPrefixCompressor(log)

	// Generate test data similar to geoip size
	prefixes := make([]netip.Prefix, 5000)
	for i := 0; i < 5000; i++ {
		a := (i >> 8) & 0xFF
		b := i & 0xFF
		prefixes[i] = mustParsePrefix(fmt.Sprintf("%d.0.%d.0/24", a%256, b))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compressor.Compress(prefixes)
	}
}

func BenchmarkPrefixCompressorSmall(b *testing.B) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	compressor := NewPrefixCompressor(log)

	prefixes := make([]netip.Prefix, 100)
	for i := 0; i < 100; i++ {
		prefixes[i] = mustParsePrefix(fmt.Sprintf("192.168.%d.0/24", i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compressor.Compress(prefixes)
	}
}
