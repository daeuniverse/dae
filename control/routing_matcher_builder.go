/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
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

// PortRuleIndex maps a destination port to a bitmap of rule indices.
// This is a semantic-preserving optimization: the bitmap preserves rule priority
// by having each bit represent whether a rule index is in the port's index.
// Note: Only covers rules 0-255; optimization degrades for higher indices.
type PortRuleIndex struct {
	Bitmap [4]uint64 // 256 bits for rules 0-255
}

// portIndexBuilder builds the port-to-rule index map.
type portIndexBuilder struct {
	portToRules map[uint16][]uint16 // Port -> list of rule indices
}

func newPortIndexBuilder() *portIndexBuilder {
	return &portIndexBuilder{
		portToRules: make(map[uint16][]uint16),
	}
}

// addRule adds a rule index to all ports that this rule may match.
//
// Semantic preservation: This optimization must preserve the original rule
// evaluation order. Key insight: we can only skip rules that DEFINITELY won't match.
//
// - MatchType_Port: Can be indexed by destination port (h_dport) because the
//   port value is known at lookup time in route().
//
// - MatchType_SourcePort: CANNOT be indexed by destination port because source
//   port (h_sport) is unknown at lookup time. Must be treated as a wildcard.
//
// - All other match types: Apply regardless of port, treated as wildcards.
func (b *portIndexBuilder) addRule(ruleIdx uint16, rule compiledRoutingMatch) {
	switch rule.matchType {
	case consts.MatchType_Port:
		// Only destination port rules can be indexed by destination port.
		// Use int to avoid infinite loop when portEnd is 65535 (uint16 max).
		for port := int(rule.portStart); port <= int(rule.portEnd); port++ {
			b.portToRules[uint16(port)] = append(b.portToRules[uint16(port)], ruleIdx)
		}
	default:
		// SourcePort and all non-port rules apply to all ports.
		// Track as wildcard rules (port 0) to be included in every port's index.
		b.portToRules[0] = append(b.portToRules[0], ruleIdx)
	}
}

// build constructs the final port index bitmap map.
// Returns a map suitable for batch updating the eBPF port_rule_index_map.
func (b *portIndexBuilder) build() map[uint16]*PortRuleIndex {
	result := make(map[uint16]*PortRuleIndex)

	// Wildcard rules apply to all ports (SourcePort, domain, IP, etc.)
	// Use nil-safe access - if no wildcard rules exist, wildcardRules will be nil
	wildcardRules := b.portToRules[0]

	for port, indices := range b.portToRules {
		// Skip port 0 - it's an internal marker for wildcard rules, not a real port
		if port == 0 {
			continue
		}

		// Combine wildcard rules with port-specific rules, then deduplicate.
		// Since wildcard rules (added first) have lower indices than port-specific
		// rules (added later), combined list is naturally sorted.
		seen := make(map[uint16]bool)
		// Add wildcard rules if any exist (nil-safe)
		for _, idx := range wildcardRules {
			seen[idx] = true
		}
		// Add port-specific rules
		for _, idx := range indices {
			seen[idx] = true
		}

		// Build bitmap: 256 bits = 4 x uint64
		// Each bit represents whether a rule index is in this port's index.
		var bitmap [4]uint64
		for idx := range seen {
			word := idx / 64
			bit := idx % 64
			bitmap[word] |= 1 << bit
		}

		result[port] = &PortRuleIndex{
			Bitmap: bitmap,
		}
	}

	return result
}

type RoutingMatcherBuilder struct {
	log                *logrus.Logger
	outboundName2Id    map[string]uint8
	bpf                *bpfObjects
	rules              []bpfMatchSet
	compiledRules      []compiledRoutingMatch
	simulatedLpmTries  [][]netip.Prefix
	simulatedDomainSet []routing.DomainSet
	fallback           *routing.Outbound
}

func NewRoutingMatcherBuilder(log *logrus.Logger, rules []*config_parser.RoutingRule, outboundName2Id map[string]uint8, bpf *bpfObjects, fallback config.FunctionOrString) (b *RoutingMatcherBuilder, err error) {
	b = &RoutingMatcherBuilder{log: log, outboundName2Id: outboundName2Id, bpf: bpf}
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
	lpmTrieIndex := len(b.simulatedLpmTries)
	b.simulatedLpmTries = append(b.simulatedLpmTries, values)
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
	lpmTrieIndex := len(b.simulatedLpmTries)
	b.simulatedLpmTries = append(b.simulatedLpmTries, values)
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
	allocStartIdx, err := reserveLpmRingSlots(lpmCount)
	if err != nil {
		return err
	}

	// Rule reload safety: clear LPM cache to avoid stale cache hits across
	// different rule generations (e.g. index reuse after config changes).
	{
		if err = BpfMapDeleteAll[bpfLpmCacheKey, uint8](b.bpf.LpmCacheMap); err != nil {
			return fmt.Errorf("clear lpm_cache_map: %w", err)
		}
	}

	// Update lpm_array_map.
	for i, cidrs := range b.simulatedLpmTries {
		realLpmIndex := (allocStartIdx + uint32(i)) % uint32(consts.MaxMatchSetLen)
		var keys []_bpfLpmKey
		var values []uint32
		for _, cidr := range cidrs {
			keys = append(keys, cidrToBpfLpmKey(cidr))
			values = append(values, 1)
		}
		m, err := b.bpf.newLpmMap(keys, values)
		if err != nil {
			return fmt.Errorf("newLpmMap: %w", err)
		}
		// We cannot invoke BpfMapBatchUpdate when value is ebpf.Map.
		if err = b.bpf.LpmArrayMap.Update(realLpmIndex, m, ebpf.UpdateAny); err != nil {
			m.Close()
			return fmt.Errorf("Update: %w", err)
		}
		m.Close()
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

	// Semantic-preserving optimization: Build port-to-rule index map.
	// This allows route_loop_cb to skip rules that definitely won't match
	// based on destination port, while preserving original rule evaluation order.
	if err = b.buildAndUpdatePortIndexMap(kernRules, log); err != nil {
		log.WithError(err).Warn("Failed to build port index map; performance optimization disabled")
		// Non-fatal: routing will work without this optimization
	}

	return nil
}

func (b *RoutingMatcherBuilder) BuildUserspace() (matcher *RoutingMatcher, err error) {
	// Build domainMatcher
	domainMatcher := domain_matcher.NewAhocorasickSlimtrie(b.log, consts.MaxMatchSetLen)
	for _, domains := range b.simulatedDomainSet {
		domainMatcher.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	// Build Ip matcher.
	var lpmMatcher []*trie.Trie
	for _, prefixes := range b.simulatedLpmTries {
		t, err := trie.NewTrieFromPrefixes(prefixes)
		if err != nil {
			return nil, err
		}
		lpmMatcher = append(lpmMatcher, t)
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

	return matcher, nil
}

// buildAndUpdatePortIndexMap builds the port-to-rule bitmap map and updates the eBPF map.
// This is a semantic-preserving optimization that allows route_loop_cb to skip
// rules that definitely won't match based on destination port using O(1) bit operations.
//
// The bitmap includes all rules that may match each port:
// - Rules with port/destination-port conditions set their corresponding bits
// - Rules without port conditions (wildcard) have all bits set
//
// route_loop_cb uses this bitmap to skip irrelevant rules while preserving
// the original rule evaluation order (0, 1, 2, ...).
func (b *RoutingMatcherBuilder) buildAndUpdatePortIndexMap(kernRules []bpfMatchSet, log *logrus.Logger) error {
	// Build port index from compiled rules
	builder := newPortIndexBuilder()

	for i := range kernRules {
		if i >= len(b.compiledRules) {
			break
		}
		compiled := b.compiledRules[i]
		builder.addRule(uint16(i), compiled)
	}

	portIndexMap := builder.build()

	// Update eBPF port_rule_index_map
	// Note: This map will be available after eBPF recompilation with the new tproxy.c
	// For now, we check if the map exists before attempting to update it.
	portRuleIndexMap := b.bpf.PortRuleIndexMap
	if portRuleIndexMap == nil {
		log.Info("Port rule index map not yet available; recompile eBPF to enable this optimization")
		return nil // Not an error - optimization is optional
	}

	// Clear all existing entries to prevent stale bitmap after config reload.
	// This follows the same pattern as LPM cache clearing (see line 518).
	// New eBPF struct size is 32 bytes (4 x uint64) instead of 68 bytes.
	if err := BpfMapDeleteAll[*uint16, [32]byte](b.bpf.PortRuleIndexMap); err != nil {
		log.WithError(err).Warn("Failed to clear port_rule_index_map; may have stale entries")
		// Non-fatal: routing will still work, just with potential stale entries
	}

	// Batch update port index map
	for port, index := range portIndexMap {
		// Convert to eBPF-compatible format
		// The eBPF struct uses: __u64 bitmap[4] = 32 bytes total

		// Since we can't directly map Go struct to eBPF struct without codegen,
		// we need to manually construct the byte array
		var value [32]byte // 4 * 8 bytes (uint64)

		// Write bitmap (little-endian)
		for i := 0; i < 4; i++ {
			bits := index.Bitmap[i]
			value[i*8] = byte(bits)
			value[i*8+1] = byte(bits >> 8)
			value[i*8+2] = byte(bits >> 16)
			value[i*8+3] = byte(bits >> 24)
			value[i*8+4] = byte(bits >> 32)
			value[i*8+5] = byte(bits >> 40)
			value[i*8+6] = byte(bits >> 48)
			value[i*8+7] = byte(bits >> 56)
		}

		if err := portRuleIndexMap.Put(&port, value); err != nil {
			return fmt.Errorf("update port_rule_index_map for port %d: %w", port, err)
		}
	}

	log.Infof("Port rule index bitmap built: %d ports indexed", len(portIndexMap))
	return nil
}
