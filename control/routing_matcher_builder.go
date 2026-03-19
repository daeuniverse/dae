/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/pkg/trie"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/routing/domain_matcher"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

// lpmMapResult holds pre-computed data for LPM map creation.
type lpmMapResult struct {
	index    uint32
	lpmIndex uint32
	keys     []_bpfLpmKey
	values   []uint32
}

// generationCounter tracks rule generations for selective cache invalidation.
var generationCounter atomic.Uint64

type RoutingMatcherBuilder struct {
	log                *logrus.Logger
	outboundName2Id    map[string]uint8
	bpf                *bpfObjects
	rules              []bpfMatchSet
	compiledRules      []compiledRoutingMatch
	simulatedLpmTries  [][]netip.Prefix
	simulatedDomainSet []routing.DomainSet
	fallback           *routing.Outbound

	// Optimization: deduplicate identical IP sets to reduce eBPF map creation.
	// Key is a hash of sorted prefixes, value stores the LPM trie index and
	// the original prefixes for collision verification.
	lpmDedup map[uint64]lpmDedupEntry
}

// lpmDedupEntry stores the deduplication mapping with collision detection.
type lpmDedupEntry struct {
	index   uint32
	prefixes []netip.Prefix
}

// hashLpmSet creates a hash key for IP prefix deduplication with collision detection.
// The hash is computed from the binary representation of sorted prefixes for efficiency.
func hashLpmSet(prefixes []netip.Prefix) uint64 {
	// Sort a copy of indices to ensure consistent hashing without modifying input
	indices := make([]int, len(prefixes))
	for i := range indices {
		indices[i] = i
	}
	sort.Slice(indices, func(i, j int) bool {
		pi := prefixes[indices[i]]
		pj := prefixes[indices[j]]
		// Compare by prefix length first, then by address bytes
		if pi.Bits() != pj.Bits() {
			return pi.Bits() < pj.Bits()
		}
		return pi.Addr().Less(pj.Addr())
	})

	// FNV-1a hash for better distribution
	const (
		fnvOffsetBasis uint64 = 14695981039346656037
		fnvPrime       uint64 = 1099511628211
	)
	h := fnvOffsetBasis
	for _, idx := range indices {
		p := prefixes[idx]
		// Hash prefix length
		h ^= uint64(p.Bits())
		h *= fnvPrime

		// Hash address bytes (supports both IPv4 and IPv6)
		addrBytes := p.Addr().AsSlice()
		for _, b := range addrBytes {
			h ^= uint64(b)
			h *= fnvPrime
		}
	}
	return h
}

// prefixesEqual checks if two prefix slices are semantically equal.
func prefixesEqual(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	// Both should already be sorted by hashLpmSet's logic
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func NewRoutingMatcherBuilder(log *logrus.Logger, rules []*config_parser.RoutingRule, outboundName2Id map[string]uint8, bpf *bpfObjects, fallback config.FunctionOrString) (b *RoutingMatcherBuilder, err error) {
	b = &RoutingMatcherBuilder{
		log:             log,
		outboundName2Id: outboundName2Id,
		bpf:             bpf,
		lpmDedup:        make(map[uint64]lpmDedupEntry),
	}
	rulesBuilder := routing.NewRulesBuilder(log)
	rulesBuilder.RegisterFunctionParser(consts.Function_Domain, routing.PlainParserFactory(b.addDomain))
	rulesBuilder.RegisterFunctionParser(consts.Function_Ip, routing.IpParserFactory(b.addIp))
	rulesBuilder.RegisterFunctionParser(consts.Function_SourceIp, routing.IpParserFactory(b.addSourceIp))
	rulesBuilder.RegisterFunctionParser(consts.Function_Port, routing.PortRangeParserFactory(b.addPort))
	rulesBuilder.RegisterFunctionParser(consts.Function_SourcePort, routing.PortRangeParserFactory(b.addSourcePort))
	rulesBuilder.RegisterFunctionParser(consts.Function_L4Proto, routing.L4ProtoParserFactory(b.addL4Proto))
	rulesBuilder.RegisterFunctionParser(consts.Function_Mac, routing.MacParserFactory(b.addSourceMac))
	rulesBuilder.RegisterFunctionParser(consts.Function_ProcessName, routing.ProcessNameParserFactory(b.addProcessName))
	rulesBuilder.RegisterFunctionParser(consts.Function_Dscp, routing.UintParserFactory(b.addDscp))
	rulesBuilder.RegisterFunctionParser(consts.Function_IpVersion, routing.IpVersionParserFactory(b.addIpVersion))
	if err = rulesBuilder.Apply(rules); err != nil {
		return nil, err
	}

	if err = b.addFallback(fallback); err != nil {
		return nil, err
	}

	return b, nil
}

func (b *RoutingMatcherBuilder) outboundToId(outbound string) (uint8, error) {
	var outboundId uint8
	switch outbound {
	case consts.OutboundLogicalOr.String():
		outboundId = uint8(consts.OutboundLogicalOr)
	case consts.OutboundLogicalAnd.String():
		outboundId = uint8(consts.OutboundLogicalAnd)
	case consts.OutboundMustRules.String():
		outboundId = uint8(consts.OutboundMustRules)
	default:
		var ok bool
		outboundId, ok = b.outboundName2Id[outbound]
		if !ok {
			return 0, fmt.Errorf("outbound (group) %v not found; please define it in section \"group\"", strconv.Quote(outbound))
		}
	}
	return outboundId, nil
}

func newCompiledRoutingBase(matchType consts.MatchType, not bool, outboundID uint8, mark uint32, must bool) compiledRoutingMatch {
	return compiledRoutingMatch{
		matchType: matchType,
		outbound:  consts.OutboundIndex(outboundID),
		not:       not,
		mark:      mark,
		must:      must,
	}
}

func (b *RoutingMatcherBuilder) appendRule(set bpfMatchSet, compiled compiledRoutingMatch) {
	b.rules = append(b.rules, set)
	b.compiledRules = append(b.compiledRules, compiled)
}

func (b *RoutingMatcherBuilder) addDomain(f *config_parser.Function, key string, values []string, outbound *routing.Outbound) (err error) {
	switch consts.RoutingDomainKey(key) {
	case consts.RoutingDomainKey_Regex,
		consts.RoutingDomainKey_Full,
		consts.RoutingDomainKey_Keyword,
		consts.RoutingDomainKey_Suffix:
	default:
		return fmt.Errorf("addDomain: unsupported key: %v", key)
	}
	b.simulatedDomainSet = append(b.simulatedDomainSet, routing.DomainSet{
		Key:       consts.RoutingDomainKey(key),
		RuleIndex: len(b.rules),
		Domains:   values,
	})
	outboundId, err := b.outboundToId(outbound.Name)
	if err != nil {
		return err
	}
	set := bpfMatchSet{
		Type:     uint8(consts.MatchType_DomainSet),
		Not:      f.Not,
		Outbound: outboundId,
		Mark:     outbound.Mark,
		Must:     outbound.Must,
	}
	b.appendRule(set, newCompiledRoutingBase(
		consts.MatchType_DomainSet, f.Not, outboundId, outbound.Mark, outbound.Must,
	))
	return nil
}

func (b *RoutingMatcherBuilder) addSourceMac(f *config_parser.Function, macAddrs [][6]byte, outbound *routing.Outbound) (err error) {
	var addr16 [16]byte
	values := make([]netip.Prefix, 0, len(macAddrs))
	for _, mac := range macAddrs {
		copy(addr16[10:], mac[:])
		prefix := netip.PrefixFrom(netip.AddrFrom16(addr16), 128)
		values = append(values, prefix)
	}
	lpmTrieIndex := len(b.simulatedLpmTries)
	b.simulatedLpmTries = append(b.simulatedLpmTries, values)
	outboundId, err := b.outboundToId(outbound.Name)
	if err != nil {
		return err
	}
	set := bpfMatchSet{
		Value:    [16]byte{},
		Type:     uint8(consts.MatchType_Mac),
		Not:      f.Not,
		Outbound: outboundId,
		Mark:     outbound.Mark,
		Must:     outbound.Must,
	}
	binary.LittleEndian.PutUint32(set.Value[:], uint32(lpmTrieIndex))
	compiled := newCompiledRoutingBase(consts.MatchType_Mac, f.Not, outboundId, outbound.Mark, outbound.Must)
	compiled.lpmIndex = uint32(lpmTrieIndex)
	b.appendRule(set, compiled)
	return nil
}

func (b *RoutingMatcherBuilder) addIp(f *config_parser.Function, values []netip.Prefix, outbound *routing.Outbound) (err error) {
	// Deduplication: check if we've seen this IP set before with collision detection
	hash := hashLpmSet(values)
	var lpmTrieIndex uint32
	if entry, exists := b.lpmDedup[hash]; exists {
		// Verify it's not a hash collision
		if prefixesEqual(entry.prefixes, values) {
			lpmTrieIndex = entry.index
		} else {
			// Hash collision detected - use a new entry
			lpmTrieIndex = uint32(len(b.simulatedLpmTries))
			b.simulatedLpmTries = append(b.simulatedLpmTries, values)
			b.lpmDedup[hash] = lpmDedupEntry{index: lpmTrieIndex, prefixes: values}
		}
	} else {
		lpmTrieIndex = uint32(len(b.simulatedLpmTries))
		b.simulatedLpmTries = append(b.simulatedLpmTries, values)
		b.lpmDedup[hash] = lpmDedupEntry{index: lpmTrieIndex, prefixes: values}
	}
	outboundId, err := b.outboundToId(outbound.Name)
	if err != nil {
		return err
	}
	set := bpfMatchSet{
		Value:    [16]byte{},
		Type:     uint8(consts.MatchType_IpSet),
		Not:      f.Not,
		Outbound: outboundId,
		Mark:     outbound.Mark,
		Must:     outbound.Must,
	}
	binary.LittleEndian.PutUint32(set.Value[:], uint32(lpmTrieIndex))
	compiled := newCompiledRoutingBase(consts.MatchType_IpSet, f.Not, outboundId, outbound.Mark, outbound.Must)
	compiled.lpmIndex = uint32(lpmTrieIndex)
	b.appendRule(set, compiled)
	return nil
}

func (b *RoutingMatcherBuilder) addPort(f *config_parser.Function, values [][2]uint16, outbound *routing.Outbound) (err error) {
	for i, value := range values {
		outboundName := consts.OutboundLogicalOr.String()
		if i == len(values)-1 {
			outboundName = outbound.Name
		}
		outboundId, err := b.outboundToId(outboundName)
		if err != nil {
			return err
		}
		set := bpfMatchSet{
			Type: uint8(consts.MatchType_Port),
			Value: bpfPortRange{
				PortStart: value[0],
				PortEnd:   value[1],
			}.Encode(),
			Not:      f.Not,
			Outbound: outboundId,
			Mark:     outbound.Mark,
			Must:     outbound.Must,
		}
		compiled := newCompiledRoutingBase(consts.MatchType_Port, f.Not, outboundId, outbound.Mark, outbound.Must)
		compiled.portStart = value[0]
		compiled.portEnd = value[1]
		b.appendRule(set, compiled)
	}
	return nil
}

func (b *RoutingMatcherBuilder) addSourceIp(f *config_parser.Function, values []netip.Prefix, outbound *routing.Outbound) (err error) {
	// Deduplication: check if we've seen this IP set before with collision detection
	hash := hashLpmSet(values)
	var lpmTrieIndex uint32
	if entry, exists := b.lpmDedup[hash]; exists {
		// Verify it's not a hash collision
		if prefixesEqual(entry.prefixes, values) {
			lpmTrieIndex = entry.index
		} else {
			// Hash collision detected - use a new entry
			lpmTrieIndex = uint32(len(b.simulatedLpmTries))
			b.simulatedLpmTries = append(b.simulatedLpmTries, values)
			b.lpmDedup[hash] = lpmDedupEntry{index: lpmTrieIndex, prefixes: values}
		}
	} else {
		lpmTrieIndex = uint32(len(b.simulatedLpmTries))
		b.simulatedLpmTries = append(b.simulatedLpmTries, values)
		b.lpmDedup[hash] = lpmDedupEntry{index: lpmTrieIndex, prefixes: values}
	}
	outboundId, err := b.outboundToId(outbound.Name)
	if err != nil {
		return err
	}
	set := bpfMatchSet{
		Value:    [16]byte{},
		Type:     uint8(consts.MatchType_SourceIpSet),
		Not:      f.Not,
		Outbound: outboundId,
		Mark:     outbound.Mark,
		Must:     outbound.Must,
	}
	binary.LittleEndian.PutUint32(set.Value[:], uint32(lpmTrieIndex))
	compiled := newCompiledRoutingBase(consts.MatchType_SourceIpSet, f.Not, outboundId, outbound.Mark, outbound.Must)
	compiled.lpmIndex = uint32(lpmTrieIndex)
	b.appendRule(set, compiled)
	return nil
}

func (b *RoutingMatcherBuilder) addSourcePort(f *config_parser.Function, values [][2]uint16, outbound *routing.Outbound) (err error) {
	for i, value := range values {
		outboundName := consts.OutboundLogicalOr.String()
		if i == len(values)-1 {
			outboundName = outbound.Name
		}
		outboundId, err := b.outboundToId(outboundName)
		if err != nil {
			return err
		}
		set := bpfMatchSet{
			Type: uint8(consts.MatchType_SourcePort),
			Value: bpfPortRange{
				PortStart: value[0],
				PortEnd:   value[1],
			}.Encode(),
			Not:      f.Not,
			Outbound: outboundId,
			Mark:     outbound.Mark,
			Must:     outbound.Must,
		}
		compiled := newCompiledRoutingBase(consts.MatchType_SourcePort, f.Not, outboundId, outbound.Mark, outbound.Must)
		compiled.portStart = value[0]
		compiled.portEnd = value[1]
		b.appendRule(set, compiled)
	}
	return nil
}

func (b *RoutingMatcherBuilder) addL4Proto(f *config_parser.Function, values consts.L4ProtoType, outbound *routing.Outbound) (err error) {
	outboundId, err := b.outboundToId(outbound.Name)
	if err != nil {
		return err
	}
	set := bpfMatchSet{
		Value:    [16]byte{byte(values)},
		Type:     uint8(consts.MatchType_L4Proto),
		Not:      f.Not,
		Outbound: outboundId,
		Mark:     outbound.Mark,
		Must:     outbound.Must,
	}
	compiled := newCompiledRoutingBase(consts.MatchType_L4Proto, f.Not, outboundId, outbound.Mark, outbound.Must)
	compiled.mask = uint8(values)
	b.appendRule(set, compiled)
	return nil
}

func (b *RoutingMatcherBuilder) addIpVersion(f *config_parser.Function, values consts.IpVersionType, outbound *routing.Outbound) (err error) {
	outboundId, err := b.outboundToId(outbound.Name)
	if err != nil {
		return err
	}
	set := bpfMatchSet{
		Value:    [16]byte{byte(values)},
		Type:     uint8(consts.MatchType_IpVersion),
		Not:      f.Not,
		Outbound: outboundId,
		Mark:     outbound.Mark,
		Must:     outbound.Must,
	}
	compiled := newCompiledRoutingBase(consts.MatchType_IpVersion, f.Not, outboundId, outbound.Mark, outbound.Must)
	compiled.mask = uint8(values)
	b.appendRule(set, compiled)
	return nil
}

func (b *RoutingMatcherBuilder) addProcessName(f *config_parser.Function, values [][consts.TaskCommLen]byte, outbound *routing.Outbound) (err error) {
	for i, value := range values {
		outboundName := consts.OutboundLogicalOr.String()
		if i == len(values)-1 {
			outboundName = outbound.Name
		}
		outboundId, err := b.outboundToId(outboundName)
		if err != nil {
			return err
		}
		matchSet := bpfMatchSet{
			Type:     uint8(consts.MatchType_ProcessName),
			Not:      f.Not,
			Outbound: outboundId,
			Mark:     outbound.Mark,
			Must:     outbound.Must,
		}
		copy(matchSet.Value[:], value[:])
		compiled := newCompiledRoutingBase(consts.MatchType_ProcessName, f.Not, outboundId, outbound.Mark, outbound.Must)
		compiled.pname = value
		b.appendRule(matchSet, compiled)
	}
	return nil
}

func (b *RoutingMatcherBuilder) addDscp(f *config_parser.Function, values []uint8, outbound *routing.Outbound) (err error) {
	for i, value := range values {
		outboundName := consts.OutboundLogicalOr.String()
		if i == len(values)-1 {
			outboundName = outbound.Name
		}
		outboundId, err := b.outboundToId(outboundName)
		if err != nil {
			return err
		}
		matchSet := bpfMatchSet{
			Type:     uint8(consts.MatchType_Dscp),
			Not:      f.Not,
			Outbound: outboundId,
			Mark:     outbound.Mark,
			Must:     outbound.Must,
		}
		matchSet.Value[0] = value
		compiled := newCompiledRoutingBase(consts.MatchType_Dscp, f.Not, outboundId, outbound.Mark, outbound.Must)
		compiled.dscp = value
		b.appendRule(matchSet, compiled)
	}
	return nil
}

func (b *RoutingMatcherBuilder) addFallback(fallbackOutbound config.FunctionOrString) (err error) {
	outbound, err := routing.ParseOutbound(config.FunctionOrStringToFunction(fallbackOutbound))
	if err != nil {
		return err
	}
	outboundId, err := b.outboundToId(outbound.Name)
	if err != nil {
		return err
	}
	set := bpfMatchSet{
		Type:     uint8(consts.MatchType_Fallback),
		Outbound: outboundId,
		Mark:     outbound.Mark,
		Must:     outbound.Must,
	}
	b.appendRule(set, newCompiledRoutingBase(
		consts.MatchType_Fallback, false, outboundId, outbound.Mark, outbound.Must,
	))
	return nil
}

// globalNextLpmIndex is process-wide to avoid reusing the same lpm_array_map
// slots during hot-reload windows where old and new rules may overlap briefly.
// BuildKernspace is expected to run serially; atomic protects against
// accidental concurrent invocation.
var globalNextLpmIndex atomic.Uint32

func getNextRingLpmIndex(count uint32) uint32 {
	maxEntries := uint32(consts.MaxMatchSetLen)
	for {
		start := globalNextLpmIndex.Load()
		next := (start + count) % maxEntries
		if globalNextLpmIndex.CompareAndSwap(start, next) {
			return start
		}
	}
}

func reserveLpmRingSlots(count uint32) (uint32, error) {
	maxEntries := uint32(consts.MaxMatchSetLen)
	if count > maxEntries {
		return 0, fmt.Errorf("too many lpm tries: %d > %d", count, maxEntries)
	}
	if count == 0 {
		return globalNextLpmIndex.Load(), nil
	}
	return getNextRingLpmIndex(count), nil
}

func rewriteKernRulesWithRingLpmIndex(rules []bpfMatchSet, allocStartIdx uint32, lpmCount uint32) ([]bpfMatchSet, error) {
	maxEntries := uint32(consts.MaxMatchSetLen)
	kernRules := make([]bpfMatchSet, len(rules))
	copy(kernRules, rules)

	for i, rule := range kernRules {
		matchType := consts.MatchType(rule.Type)
		switch matchType {
		case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
			oldLpmIndex := binary.LittleEndian.Uint32(rule.Value[:4])
			if oldLpmIndex >= lpmCount {
				return nil, fmt.Errorf("bad lpm index in rule[%d]: %d >= %d", i, oldLpmIndex, lpmCount)
			}
			newLpmIndex := (allocStartIdx + oldLpmIndex) % maxEntries
			binary.LittleEndian.PutUint32(kernRules[i].Value[:4], newLpmIndex)
		}
	}
	return kernRules, nil
}

// BuildKernspace constructs BPF maps and loads routing rules into kernel space.
//
// IMPORTANT: This method MUST be called serially (not concurrently). The control plane
// ensures serialization through higher-level locks. Concurrent invocations will cause
// race conditions in globalNextLpmIndex allocation and LPM map updates.
//
// Thread Safety: NOT thread-safe. Caller must ensure mutual exclusion.
func (b *RoutingMatcherBuilder) BuildKernspace(log *logrus.Logger) (err error) {
	lpmCount := uint32(len(b.simulatedLpmTries))
	if lpmCount > 0 {
		dedupCount := uint32(len(b.lpmDedup))
		reduction := float64(lpmCount-dedupCount) / float64(lpmCount) * 100
		log.Infof("Building %d LPM tries (deduplicated from %d sets, %.1f%% reduction)",
			dedupCount, lpmCount, reduction)
	}
	allocStartIdx, err := reserveLpmRingSlots(lpmCount)
	if err != nil {
		return err
	}

	// Pre-allocate results slice with exact capacity
	results := make([]lpmMapResult, len(b.simulatedLpmTries))

	// Pre-convert all CIDRs to BPF keys in parallel for better cache utilization
	numWorkers := runtime.GOMAXPROCS(0)
	if numWorkers > 8 {
		numWorkers = 8
	}
	if lpmCount < 4 {
		numWorkers = 1
	}

	if numWorkers > 1 && len(b.simulatedLpmTries) > 1 {
		// Parallel conversion
		sem := make(chan struct{}, numWorkers)
		var wg sync.WaitGroup
		for i := range b.simulatedLpmTries {
			wg.Add(1)
			sem <- struct{}{}
			go func(idx int) {
				defer func() { <-sem }()
				defer wg.Done()

				cidrs := b.simulatedLpmTries[idx]
				// Pre-allocate with exact capacity to avoid append growth
				keys := make([]_bpfLpmKey, len(cidrs))
				values := make([]uint32, len(cidrs))

				for j, cidr := range cidrs {
					keys[j] = cidrToBpfLpmKey(cidr)
					values[j] = 1
				}

				results[idx] = lpmMapResult{
					index:    uint32(idx),
					lpmIndex: (allocStartIdx + uint32(idx)) % uint32(consts.MaxMatchSetLen),
					keys:     keys,
					values:   values,
				}
			}(i)
		}
		wg.Wait()
	} else {
		// Serial conversion for small sets
		for i, cidrs := range b.simulatedLpmTries {
			keys := make([]_bpfLpmKey, len(cidrs))
			values := make([]uint32, len(cidrs))
			for j, cidr := range cidrs {
				keys[j] = cidrToBpfLpmKey(cidr)
				values[j] = 1
			}
			results[i] = lpmMapResult{
				index:    uint32(i),
				lpmIndex: (allocStartIdx + uint32(i)) % uint32(consts.MaxMatchSetLen),
				keys:     keys,
				values:   values,
			}
		}
	}

	// Create and update LPM maps in parallel
	if numWorkers > 1 && len(results) > 1 {
		// Parallel path
		sem := make(chan struct{}, numWorkers)
		var wg sync.WaitGroup
		var firstErr error
		var mu sync.Mutex

		for i := range results {
			wg.Add(1)
			sem <- struct{}{}
			go func(idx int) {
				defer func() { <-sem }()
				defer wg.Done()

				r := results[idx]
				m, mapErr := b.bpf.newLpmMap(r.keys, r.values)
				if mapErr != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("newLpmMap at index %d: %w", idx, mapErr)
					}
					mu.Unlock()
					return
				}

				mu.Lock()
				mapErr = b.bpf.LpmArrayMap.Update(r.lpmIndex, m, ebpf.UpdateAny)
				mu.Unlock()
				if mapErr != nil {
					m.Close()
					mu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("Update lpm_array_map[%d]: %w", r.lpmIndex, mapErr)
					}
					mu.Unlock()
					return
				}
				m.Close()
			}(i)
		}
		wg.Wait()

		if firstErr != nil {
			return firstErr
		}
	} else {
		// Serial path for small sets
		for _, r := range results {
			m, err := b.bpf.newLpmMap(r.keys, r.values)
			if err != nil {
				return fmt.Errorf("newLpmMap: %w", err)
			}
			if err = b.bpf.LpmArrayMap.Update(r.lpmIndex, m, ebpf.UpdateAny); err != nil {
				m.Close()
				return fmt.Errorf("Update: %w", err)
			}
			m.Close()
		}
	}

	// Write routings.
	// Fallback rule MUST be the last.
	if b.rules[len(b.rules)-1].Type != uint8(consts.MatchType_Fallback) {
		return fmt.Errorf("fallback rule MUST be the last")
	}
	routingsLen := uint32(len(b.rules))
	kernRules, err := rewriteKernRulesWithRingLpmIndex(b.rules, allocStartIdx, lpmCount)
	if err != nil {
		return err
	}
	routingsKeys := common.ARangeU32(routingsLen)
	if _, err = BpfMapBatchUpdate(b.bpf.RoutingMap, routingsKeys, kernRules, &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		return fmt.Errorf("BpfMapBatchUpdate: %w", err)
	}
	if err = b.bpf.RoutingMetaMap.Update(uint32(0), routingsLen, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update routing_meta_map: %w", err)
	}
	log.Infof("Routing match set len: %v/%v", len(b.rules), consts.MaxMatchSetLen)

	return nil
}

func (b *RoutingMatcherBuilder) BuildUserspace() (matcher *RoutingMatcher, err error) {
	// Build domainMatcher first (it has its own parallelization)
	domainMatcher := domain_matcher.NewAhocorasickSlimtrie(b.log, consts.MaxMatchSetLen)
	for _, domains := range b.simulatedDomainSet {
		domainMatcher.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}

	// Build IP matcher with parallel LPM trie construction for better performance.
	var lpmMatcher []*trie.Trie
	numTries := len(b.simulatedLpmTries)

	// Pre-allocate slice with exact capacity
	lpmMatcher = make([]*trie.Trie, numTries)

	if numTries > 4 {
		// Parallel path for larger sets
		numWorkers := runtime.GOMAXPROCS(0)
		if numWorkers > 8 {
			numWorkers = 8
		}

		// Use buffered channel as semaphore
		sem := make(chan struct{}, numWorkers)
		var wg sync.WaitGroup
		var mu sync.Mutex
		var buildErr error

		for i := range b.simulatedLpmTries {
			wg.Add(1)
			sem <- struct{}{}
			go func(idx int) {
				defer func() { <-sem }()
				defer wg.Done()

				// Direct slice access avoids closure allocation
				prefixes := b.simulatedLpmTries[idx]
				t, trieErr := trie.NewTrieFromPrefixes(prefixes)
				if trieErr != nil {
					mu.Lock()
					if buildErr == nil {
						buildErr = trieErr
					}
					mu.Unlock()
					return
				}

				// Direct assignment avoids mutex in most cases
				// (each goroutine writes to its own index)
				lpmMatcher[idx] = t
			}(i)
		}
		wg.Wait()

		if buildErr != nil {
			return nil, buildErr
		}
	} else {
		// Serial path for small sets - faster due to no goroutine overhead
		for i, prefixes := range b.simulatedLpmTries {
			t, err := trie.NewTrieFromPrefixes(prefixes)
			if err != nil {
				return nil, err
			}
			lpmMatcher[i] = t
		}
	}

	if err = domainMatcher.Build(); err != nil {
		return nil, err
	}

	// Write routings.
	// Fallback rule MUST be the last.
	if b.rules[len(b.rules)-1].Type != uint8(consts.MatchType_Fallback) {
		return nil, fmt.Errorf("fallback rule MUST be the last")
	}
	compiledMatches := b.compiledRules
	if len(compiledMatches) != len(b.rules) {
		compiledMatches, err = compileRoutingMatches(b.rules)
		if err != nil {
			return nil, fmt.Errorf("compile routing matches: %w", err)
		}
	}

	matcher = &RoutingMatcher{
		lpmMatcher:      lpmMatcher,
		domainMatcher:   domainMatcher,
		compiledMatches: compiledMatches,
	}

	// Memory optimization: Release large temporary data structures
	// after building the matcher to reduce memory footprint.
	b.simulatedDomainSet = nil
	b.simulatedLpmTries = nil
	b.rules = nil
	b.compiledRules = nil
	b.lpmDedup = nil

	return matcher, nil
}
