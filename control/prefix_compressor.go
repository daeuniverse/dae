/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sort"

	"github.com/sirupsen/logrus"
)

// PrefixCompressor compresses IP prefix lists by removing duplicates
// and redundant entries (those covered by broader prefixes).
type PrefixCompressor struct {
	log *logrus.Logger
}

// NewPrefixCompressor creates a new compressor instance.
func NewPrefixCompressor(log *logrus.Logger) *PrefixCompressor {
	return &PrefixCompressor{log: log}
}

// Compress optimizes a list of IP prefixes by:
// 1. Removing exact duplicates
// 2. Removing prefixes covered by broader ones
// Returns the compressed list, original count, and number of entries removed.
func (pc *PrefixCompressor) Compress(prefixes []netip.Prefix) (compressed []netip.Prefix, originalCount int, removedCount int) {
	originalCount = len(prefixes)
	if originalCount == 0 {
		return prefixes, 0, 0
	}

	// Step 1: Remove exact duplicates using a map
	uniqueMap := make(map[string]bool, originalCount)
	unique := make([]netip.Prefix, 0, originalCount)
	for _, p := range prefixes {
		key := p.String()
		if !uniqueMap[key] {
			uniqueMap[key] = true
			unique = append(unique, p)
		}
	}
	removedCount = originalCount - len(unique)

	// Step 2: Remove redundant prefixes (those covered by broader ones)
	// Sort by prefix length ascending (broader prefixes first)
	sort.Slice(unique, func(i, j int) bool {
		if unique[i].Bits() != unique[j].Bits() {
			return unique[i].Bits() < unique[j].Bits()
		}
		return unique[i].Addr().Less(unique[j].Addr())
	})

	nonRedundant := make([]netip.Prefix, 0, len(unique))
	for _, candidate := range unique {
		isCovered := false
		for _, broader := range nonRedundant {
			if broader.Bits() <= candidate.Bits() {
				if broader.Contains(candidate.Addr()) {
					isCovered = true
					break
				}
			}
		}
		if !isCovered {
			nonRedundant = append(nonRedundant, candidate)
		} else {
			removedCount++
		}
	}

	compressed = nonRedundant

	if removedCount > 0 && pc.log != nil {
		reduction := float64(removedCount) / float64(originalCount) * 100
		pc.log.Debugf("Prefix compression: %d -> %d entries (%.1f%% reduction, %d removed)",
			originalCount, len(compressed), reduction, removedCount)
	}

	return compressed, originalCount, removedCount
}

// OptimizePrefixes applies compression to a list of prefixes.
// This is a convenience function for one-shot optimization.
func OptimizePrefixes(log *logrus.Logger, prefixes []netip.Prefix) []netip.Prefix {
	compressor := NewPrefixCompressor(log)
	result, _, _ := compressor.Compress(prefixes)
	return result
}

// CompressionStats holds statistics about a compression operation.
type CompressionStats struct {
	OriginalEntries   int
	CompressedEntries int
	RemovedCount      int
	ReductionPercent  float64
}

// GetStats returns compression statistics.
func (pc *PrefixCompressor) GetStats(original, compressed []netip.Prefix) CompressionStats {
	origLen := len(original)
	compLen := len(compressed)
	removed := origLen - compLen

	return CompressionStats{
		OriginalEntries:   origLen,
		CompressedEntries: compLen,
		RemovedCount:      removed,
		ReductionPercent:  float64(removed) / float64(origLen) * 100,
	}
}
