/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
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

type RoutingMatcherBuilder struct {
	log                *logrus.Logger
	outboundName2Id    map[string]uint8
	bpf                *bpfObjects
	rules              []bpfMatchSet
	compiledRules      []compiledRoutingMatch
	predicateGroups    []routingMatcherPredicateGroupSpan
	simulatedLpmTries  [][]netip.Prefix
	simulatedDomainSet []routing.DomainSet
	// packetMetadataSensitiveRouting is true when routing rules depend on
	// metadata that userspace UDP handling cannot reconstruct from payload
	// alone. In that case, broad UDP endpoint/routing-result reuse is unsafe.
	packetMetadataSensitiveRouting bool
	// referencedOutbounds tracks outbound names referenced by routing rules.
	// This is used to limit health checks to only nodes in used groups.
	referencedOutbounds map[string]struct{}

	// Optimization: deduplicate identical IP sets to reduce eBPF map creation.
	// Key is a hash of sorted prefixes, value stores the LPM trie index and
	// the original prefixes for collision verification.
	lpmDedup map[uint64]lpmDedupEntry
}

type routingKernspaceSnapshot struct {
	rules             []bpfMatchSet
	simulatedLpmTries [][]netip.Prefix
	dedupCount        int
}

// lpmDedupEntry stores the deduplication mapping with collision detection.
type lpmDedupEntry struct {
	index    uint32
	prefixes []netip.Prefix
}

func bpfBool(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}

// canonicalizePrefixes sorts prefixes by (bits, address) and drops exact
// duplicates. It deliberately performs no address normalization: the 4-in-6
// normalization (::ffff:a.b.c.d/n written with an IPv4 bit count) is owned by
// pkg/trie.Prefix2bin128 for the userspace matcher and by cidrToBpfLpmKey for
// the kernel LPM, which both map the mapped and the plain spelling onto the
// same key. Adding a second normalization point here would only make the two
// spellings compare equal for dedup while hiding which component owns the
// semantic decision.
func canonicalizePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	canonical := append([]netip.Prefix(nil), prefixes...)
	sort.Slice(canonical, func(i, j int) bool {
		if canonical[i].Bits() != canonical[j].Bits() {
			return canonical[i].Bits() < canonical[j].Bits()
		}
		return canonical[i].Addr().Less(canonical[j].Addr())
	})
	deduped := canonical[:0]
	for _, prefix := range canonical {
		if len(deduped) == 0 || deduped[len(deduped)-1] != prefix {
			deduped = append(deduped, prefix)
		}
	}
	return deduped
}

// hashLpmSet creates a hash key for IP prefix deduplication with collision detection.
// The hash is computed from the binary representation of canonicalized prefixes.
func hashLpmSet(prefixes []netip.Prefix) uint64 {
	// FNV-1a hash for better distribution
	const (
		fnvOffsetBasis uint64 = 14695981039346656037
		fnvPrime       uint64 = 1099511628211
	)
	h := fnvOffsetBasis
	for _, p := range prefixes {
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
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func NewRoutingMatcherBuilderFromProgram(log *logrus.Logger, program *routing.NormalizedProgram, outboundName2Id map[string]uint8, bpf *bpfObjects) (b *RoutingMatcherBuilder, err error) {
	if program == nil {
		return nil, fmt.Errorf("routing program is nil")
	}
	ruleCap := len(program.Rules)
	b = &RoutingMatcherBuilder{
		log:             log,
		outboundName2Id: outboundName2Id,
		bpf:             bpf,
		// Pre-allocate the per-rule accumulator slices to the known rule count.
		// Each routing rule emits at least one compiled predicate, so this is a
		// safe lower bound that avoids the early append-growth reallocations on
		// the (cold) build/reload path. simulatedDomainSet/simulatedLpmTries are
		// left nil because their counts depend on rule type, not rule count.
		rules:               make([]bpfMatchSet, 0, ruleCap),
		compiledRules:       make([]compiledRoutingMatch, 0, ruleCap),
		predicateGroups:     make([]routingMatcherPredicateGroupSpan, 0, ruleCap),
		lpmDedup:            make(map[uint64]lpmDedupEntry),
		referencedOutbounds: make(map[string]struct{}),
	}
	if err = program.Lower(log, b.registerProgramParsers, b.addFallback); err != nil {
		return nil, err
	}
	return b, nil
}

// routingProgramSink receives the parsed operands of one routing rule function.
// The run path compiles and stores them (RoutingMatcherBuilder); the validate
// path only resolves the referenced outbound name.
type routingProgramSink interface {
	// registerParser installs one parser, adding whatever bookkeeping the sink
	// needs. The run path records predicate-group spans around every call, so
	// registration must stay behind this method instead of writing straight to
	// the RulesBuilder.
	registerParser(rulesBuilder *routing.RulesBuilder, name string, parser routing.FunctionParser)
	// The ten addX methods mirror the RoutingMatcherBuilder methods of the same
	// name; their signatures are fixed by the routing.*ParserFactory factories.
	addDomain(f *config_parser.Function, key string, values []string, outbound *routing.Outbound) error
	addIp(f *config_parser.Function, values []netip.Prefix, outbound *routing.Outbound) error
	addSourceIp(f *config_parser.Function, values []netip.Prefix, outbound *routing.Outbound) error
	addPort(f *config_parser.Function, values [][2]uint16, outbound *routing.Outbound) error
	addSourcePort(f *config_parser.Function, values [][2]uint16, outbound *routing.Outbound) error
	addL4Proto(f *config_parser.Function, values consts.L4ProtoType, outbound *routing.Outbound) error
	addSourceMac(f *config_parser.Function, macAddrs [][6]byte, outbound *routing.Outbound) error
	addProcessName(f *config_parser.Function, values [][consts.TaskCommLen]byte, outbound *routing.Outbound) error
	addDscp(f *config_parser.Function, values []uint8, outbound *routing.Outbound) error
	addIpVersion(f *config_parser.Function, values consts.IpVersionType, outbound *routing.Outbound) error
}

// registerRoutingProgramParsers is the single source of truth for the routing
// rule function registry shared by the run and validate paths. Any new routing
// function MUST be added here so `dae validate` cannot silently accept what
// `dae run` would reject.
func registerRoutingProgramParsers(b *routing.RulesBuilder, sink routingProgramSink) {
	sink.registerParser(b, consts.Function_Domain, routing.PlainParserFactory(
		func(f *config_parser.Function, key string, values []string, outbound *routing.Outbound) error {
			// The accepted domain keys are checked here, not in a sink, so both
			// paths agree on which keys are legal.
			switch consts.RoutingDomainKey(key) {
			case consts.RoutingDomainKey_Regex,
				consts.RoutingDomainKey_Full,
				consts.RoutingDomainKey_Keyword,
				consts.RoutingDomainKey_Suffix:
			default:
				return fmt.Errorf("addDomain: unsupported key: %v", key)
			}
			return sink.addDomain(f, key, values, outbound)
		}))
	sink.registerParser(b, consts.Function_Ip, routing.IpParserFactory(sink.addIp))
	sink.registerParser(b, consts.Function_SourceIp, routing.IpParserFactory(sink.addSourceIp))
	sink.registerParser(b, consts.Function_Port, routing.PortRangeParserFactory(sink.addPort))
	sink.registerParser(b, consts.Function_SourcePort, routing.PortRangeParserFactory(sink.addSourcePort))
	sink.registerParser(b, consts.Function_L4Proto, routing.L4ProtoParserFactory(sink.addL4Proto))
	sink.registerParser(b, consts.Function_Mac, routing.MacParserFactory(sink.addSourceMac))
	sink.registerParser(b, consts.Function_ProcessName, routing.ProcessNameParserFactory(sink.addProcessName))
	sink.registerParser(b, consts.Function_Dscp, routing.UintParserFactory(sink.addDscp))
	sink.registerParser(b, consts.Function_IpVersion, routing.IpVersionParserFactory(sink.addIpVersion))
}

// routingProgramValidationSink validates rule operands without compiling them.
// It is what makes `dae validate` run the very same parsers as `dae run`.
type routingProgramValidationSink struct {
	resolveOutbound func(name string) error
}

func (s *routingProgramValidationSink) registerParser(rulesBuilder *routing.RulesBuilder, name string, parser routing.FunctionParser) {
	rulesBuilder.RegisterFunctionParser(name, parser)
}

func (s *routingProgramValidationSink) resolve(outbound *routing.Outbound) error {
	if s == nil || s.resolveOutbound == nil || outbound == nil {
		return nil
	}
	return s.resolveOutbound(outbound.Name)
}

func (s *routingProgramValidationSink) addDomain(_ *config_parser.Function, _ string, _ []string, outbound *routing.Outbound) error {
	return s.resolve(outbound)
}

func (s *routingProgramValidationSink) addIp(_ *config_parser.Function, _ []netip.Prefix, outbound *routing.Outbound) error {
	return s.resolve(outbound)
}

func (s *routingProgramValidationSink) addSourceIp(_ *config_parser.Function, _ []netip.Prefix, outbound *routing.Outbound) error {
	return s.resolve(outbound)
}

func (s *routingProgramValidationSink) addPort(_ *config_parser.Function, _ [][2]uint16, outbound *routing.Outbound) error {
	return s.resolve(outbound)
}

func (s *routingProgramValidationSink) addSourcePort(_ *config_parser.Function, _ [][2]uint16, outbound *routing.Outbound) error {
	return s.resolve(outbound)
}

func (s *routingProgramValidationSink) addL4Proto(_ *config_parser.Function, _ consts.L4ProtoType, outbound *routing.Outbound) error {
	return s.resolve(outbound)
}

func (s *routingProgramValidationSink) addSourceMac(_ *config_parser.Function, _ [][6]byte, outbound *routing.Outbound) error {
	return s.resolve(outbound)
}

func (s *routingProgramValidationSink) addProcessName(_ *config_parser.Function, _ [][consts.TaskCommLen]byte, outbound *routing.Outbound) error {
	return s.resolve(outbound)
}

func (s *routingProgramValidationSink) addDscp(_ *config_parser.Function, _ []uint8, outbound *routing.Outbound) error {
	return s.resolve(outbound)
}

func (s *routingProgramValidationSink) addIpVersion(_ *config_parser.Function, _ consts.IpVersionType, outbound *routing.Outbound) error {
	return s.resolve(outbound)
}

// RegisterRoutingProgramParsers installs the routing program function parsers
// shared by the run and validate paths. Any new routing function MUST be added
// here so `dae validate` cannot silently accept what `run` would reject.
// resolveOutbound mirrors RoutingMatcherBuilder.outboundToId's root-namespace
// check (the implicit direct/block/logical outbounds plus the configured
// groups); it is only consulted, never stored.
func RegisterRoutingProgramParsers(b *routing.RulesBuilder, resolveOutbound func(string) error) {
	if b == nil {
		return
	}
	registerRoutingProgramParsers(b, &routingProgramValidationSink{resolveOutbound: resolveOutbound})
}

// registerProgramParsers is the run path's entry point: the matcher builder
// both validates and compiles every operand.
func (b *RoutingMatcherBuilder) registerProgramParsers(rulesBuilder *routing.RulesBuilder) {
	registerRoutingProgramParsers(rulesBuilder, b)
}

func (b *RoutingMatcherBuilder) registerParser(rulesBuilder *routing.RulesBuilder, name string, parser routing.FunctionParser) {
	rulesBuilder.RegisterFunctionParser(name, func(
		log *logrus.Logger,
		function *config_parser.Function,
		key string,
		values []string,
		overrideOutbound *routing.Outbound,
	) error {
		start := len(b.compiledRules)
		if err := parser(log, function, key, values, overrideOutbound); err != nil {
			return err
		}
		b.predicateGroups = append(b.predicateGroups, routingMatcherPredicateGroupSpan{
			name:  function.Name,
			key:   key,
			not:   function.Not,
			start: start,
			end:   len(b.compiledRules),
		})
		return nil
	})
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
	case consts.OutboundControlPlaneRouting.String():
		// Implicit sniff-punt lines steer unknown-domain traffic of a device
		// whitelist to userspace for sniffed-domain re-routing. They carry no
		// group and must never register as a health-checked reference.
		outboundId = uint8(consts.OutboundControlPlaneRouting)
	default:
		var ok bool
		outboundId, ok = b.outboundName2Id[outbound]
		if !ok {
			return 0, fmt.Errorf("outbound (group) %v not found; please define it in section \"group\"", strconv.Quote(outbound))
		}
		// Track that this outbound group is referenced by routing rules.
		// This is used to limit health checks to only used nodes.
		b.referencedOutbounds[outbound] = struct{}{}
	}
	return outboundId, nil
}

// GetReferencedOutbounds returns the set of outbound group names referenced by routing rules.
// This is used to limit health checks to only nodes in used groups.
func (b *RoutingMatcherBuilder) GetReferencedOutbounds() map[string]struct{} {
	return b.referencedOutbounds
}

func (b *RoutingMatcherBuilder) UsesPacketMetadataRouting() bool {
	return b.packetMetadataSensitiveRouting
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
		Not:      bpfBool(f.Not),
		Outbound: outboundId,
		Mark:     outbound.Mark,
		Must:     bpfBool(outbound.Must),
	}
	b.appendRule(set, newCompiledRoutingBase(
		consts.MatchType_DomainSet, f.Not, outboundId, outbound.Mark, outbound.Must,
	))
	return nil
}

func (b *RoutingMatcherBuilder) addSourceMac(f *config_parser.Function, macAddrs [][6]byte, outbound *routing.Outbound) (err error) {
	if f.Not {
		// Automatically exclude Zero MAC for negative MAC rules to avoid capturing internal/local traffic.
		macAddrs = append(macAddrs, [6]byte{})
	}
	b.packetMetadataSensitiveRouting = true
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
		Not:      bpfBool(f.Not),
		Outbound: outboundId,
		Mark:     outbound.Mark,
		Must:     bpfBool(outbound.Must),
	}
	nativeBpfABI.putUint32(set.Value[:], uint32(lpmTrieIndex))
	compiled := newCompiledRoutingBase(consts.MatchType_Mac, f.Not, outboundId, outbound.Mark, outbound.Must)
	compiled.lpmIndex = uint32(lpmTrieIndex)
	b.appendRule(set, compiled)
	return nil
}

func (b *RoutingMatcherBuilder) addIp(f *config_parser.Function, values []netip.Prefix, outbound *routing.Outbound) (err error) {
	values = canonicalizePrefixes(values)
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
		Not:      bpfBool(f.Not),
		Outbound: outboundId,
		Mark:     outbound.Mark,
		Must:     bpfBool(outbound.Must),
	}
	nativeBpfABI.putUint32(set.Value[:], lpmTrieIndex)
	compiled := newCompiledRoutingBase(consts.MatchType_IpSet, f.Not, outboundId, outbound.Mark, outbound.Must)
	compiled.lpmIndex = lpmTrieIndex
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
			Not:      bpfBool(f.Not),
			Outbound: outboundId,
			Mark:     outbound.Mark,
			Must:     bpfBool(outbound.Must),
		}
		compiled := newCompiledRoutingBase(consts.MatchType_Port, f.Not, outboundId, outbound.Mark, outbound.Must)
		compiled.portStart = value[0]
		compiled.portEnd = value[1]
		b.appendRule(set, compiled)
	}
	return nil
}

func (b *RoutingMatcherBuilder) addSourceIp(f *config_parser.Function, values []netip.Prefix, outbound *routing.Outbound) (err error) {
	values = canonicalizePrefixes(values)
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
		Not:      bpfBool(f.Not),
		Outbound: outboundId,
		Mark:     outbound.Mark,
		Must:     bpfBool(outbound.Must),
	}
	nativeBpfABI.putUint32(set.Value[:], lpmTrieIndex)
	compiled := newCompiledRoutingBase(consts.MatchType_SourceIpSet, f.Not, outboundId, outbound.Mark, outbound.Must)
	compiled.lpmIndex = lpmTrieIndex
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
			Not:      bpfBool(f.Not),
			Outbound: outboundId,
			Mark:     outbound.Mark,
			Must:     bpfBool(outbound.Must),
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
		Not:      bpfBool(f.Not),
		Outbound: outboundId,
		Mark:     outbound.Mark,
		Must:     bpfBool(outbound.Must),
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
		Not:      bpfBool(f.Not),
		Outbound: outboundId,
		Mark:     outbound.Mark,
		Must:     bpfBool(outbound.Must),
	}
	compiled := newCompiledRoutingBase(consts.MatchType_IpVersion, f.Not, outboundId, outbound.Mark, outbound.Must)
	compiled.mask = uint8(values)
	b.appendRule(set, compiled)
	return nil
}

func (b *RoutingMatcherBuilder) addProcessName(f *config_parser.Function, values [][consts.TaskCommLen]byte, outbound *routing.Outbound) (err error) {
	b.packetMetadataSensitiveRouting = true
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
			Not:      bpfBool(f.Not),
			Outbound: outboundId,
			Mark:     outbound.Mark,
			Must:     bpfBool(outbound.Must),
		}
		copy(matchSet.Value[:], value[:])
		compiled := newCompiledRoutingBase(consts.MatchType_ProcessName, f.Not, outboundId, outbound.Mark, outbound.Must)
		compiled.pname = value
		b.appendRule(matchSet, compiled)
	}
	return nil
}

func (b *RoutingMatcherBuilder) addDscp(f *config_parser.Function, values []uint8, outbound *routing.Outbound) (err error) {
	b.packetMetadataSensitiveRouting = true
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
			Not:      bpfBool(f.Not),
			Outbound: outboundId,
			Mark:     outbound.Mark,
			Must:     bpfBool(outbound.Must),
		}
		matchSet.Value[0] = value
		compiled := newCompiledRoutingBase(consts.MatchType_Dscp, f.Not, outboundId, outbound.Mark, outbound.Must)
		compiled.dscp = value
		b.appendRule(matchSet, compiled)
	}
	return nil
}

func (b *RoutingMatcherBuilder) addFallback(fallbackOutbound config.FunctionOrString) (err error) {
	fallbackFunc, err := config.ParseFunctionOrString(fallbackOutbound)
	if err != nil {
		return err
	}
	outbound, err := routing.ParseOutbound(fallbackFunc)
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
		Must:     bpfBool(outbound.Must),
	}
	b.appendRule(set, newCompiledRoutingBase(
		consts.MatchType_Fallback, false, outboundId, outbound.Mark, outbound.Must,
	))
	return nil
}

// globalNextLpmIndex allocates local LPM indexes across builds, reducing
// reuse when a slot is rebuilt. BuildKernspace is expected to run serially;
// lpmBuildMu makes that ownership explicit for the shared map and ring.
var (
	globalNextLpmIndex atomic.Uint32
	lpmBuildMu         sync.Mutex
)

func routingEpochSlotBase(slot uint32) (uint32, error) {
	if !validRoutingEpochSlot(slot) {
		return 0, fmt.Errorf("invalid routing epoch slot %d", slot)
	}
	return slot * uint32(consts.MaxMatchSetLen), nil
}

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

func (b *RoutingMatcherBuilder) KernspaceSnapshot() *routingKernspaceSnapshot {
	if b == nil {
		return nil
	}
	return &routingKernspaceSnapshot{
		rules:             b.rules,
		simulatedLpmTries: b.simulatedLpmTries,
		dedupCount:        len(b.lpmDedup),
	}
}

func rewriteKernRulesWithRingLpmIndex(rules []bpfMatchSet, allocStartIdx uint32, lpmCount uint32) ([]bpfMatchSet, error) {
	maxEntries := uint32(consts.MaxMatchSetLen)
	kernRules := make([]bpfMatchSet, len(rules))
	copy(kernRules, rules)

	for i, rule := range kernRules {
		matchType := consts.MatchType(rule.Type)
		switch matchType {
		case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
			oldLpmIndex := nativeBpfABI.uint32(rule.Value[:4])
			if oldLpmIndex >= lpmCount {
				return nil, fmt.Errorf("bad lpm index in rule[%d]: %d >= %d", i, oldLpmIndex, lpmCount)
			}
			newLpmIndex := (allocStartIdx + oldLpmIndex) % maxEntries
			nativeBpfABI.putUint32(kernRules[i].Value[:4], newLpmIndex)
		}
	}
	return kernRules, nil
}

func buildRoutingKernspaceForSlot(
	log *logrus.Logger,
	bpf *bpfObjects,
	rules []bpfMatchSet,
	simulatedLpmTries [][]netip.Prefix,
	dedupCount int,
	slot uint32,
) (usedIndices []uint32, err error) {
	slotBase, err := routingEpochSlotBase(slot)
	if err != nil {
		return nil, err
	}
	if bpf == nil {
		return nil, fmt.Errorf("nil bpf objects")
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no routing rules to build")
	}
	if len(rules) > consts.MaxMatchSetLen {
		return nil, fmt.Errorf("too many routing rules: %d > %d", len(rules), consts.MaxMatchSetLen)
	}

	// The ring cursor and the map-of-maps are shared by all generations that
	// use this datapath. Serialize builders so a rollback cannot restore over
	// another build's newly installed entries.
	lpmBuildMu.Lock()
	defer lpmBuildMu.Unlock()

	lpmCount := uint32(len(simulatedLpmTries))
	if lpmCount > 0 {
		dedupCountU32 := uint32(dedupCount)
		reduction := float64(lpmCount-dedupCountU32) / float64(lpmCount) * 100
		log.Infof("Building %d LPM tries (deduplicated from %d sets, %.1f%% reduction)",
			dedupCountU32, lpmCount, reduction)
	}
	allocStartIdx, err := reserveLpmRingSlots(lpmCount)
	if err != nil {
		return nil, err
	}

	// Pre-allocate results slice with exact capacity
	results := make([]lpmMapResult, len(simulatedLpmTries))

	// Pre-convert all CIDRs to BPF keys in parallel for better cache utilization
	numWorkers := min(runtime.GOMAXPROCS(0), 8)
	if lpmCount < 4 {
		numWorkers = 1
	}

	if numWorkers > 1 && len(simulatedLpmTries) > 1 {
		// Parallel conversion
		sem := make(chan struct{}, numWorkers)
		var wg sync.WaitGroup
		for i := range simulatedLpmTries {
			wg.Add(1)
			sem <- struct{}{}
			go func(idx int) {
				defer func() { <-sem }()
				defer wg.Done()

				cidrs := simulatedLpmTries[idx]
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
		for i, cidrs := range simulatedLpmTries {
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

	// Keep the previous inner map for every slot touched by this build. A
	// failed build may be rebuilding an existing slot, so deleting a reserved
	// key would destroy the previous generation's routing state.
	lpmBackups := make(map[uint32]*ebpf.Map, len(results))
	defer func() {
		for _, inner := range lpmBackups {
			_ = inner.Close()
		}
	}()
	if lpmCount > 0 {
		if bpf.LpmArrayMap == nil {
			return nil, fmt.Errorf("nil lpm_array_map")
		}
		for _, r := range results {
			mapIndex := slotBase + r.lpmIndex
			var inner *ebpf.Map
			lookupErr := bpf.LpmArrayMap.Lookup(mapIndex, &inner)
			if lookupErr != nil {
				if !errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
					return nil, fmt.Errorf("snapshot lpm_array_map[%d]: %w", mapIndex, lookupErr)
				}
				continue
			}
			if inner != nil {
				lpmBackups[mapIndex] = inner
			}
		}
	}

	installedLpmIndices := make([]uint32, 0, len(results))
	var installedLpmMu sync.Mutex
	defer func() {
		if err == nil {
			return
		}
		for _, mapIndex := range installedLpmIndices {
			if inner, ok := lpmBackups[mapIndex]; ok {
				if restoreErr := bpf.LpmArrayMap.Update(mapIndex, inner, ebpf.UpdateAny); restoreErr != nil {
					log.Warnf("restore lpm_array_map[%d] after failed build: %v", mapIndex, restoreErr)
				}
				continue
			}
			if delErr := bpf.LpmArrayMap.Delete(mapIndex); delErr != nil && !errors.Is(delErr, ebpf.ErrKeyNotExist) {
				log.Warnf("roll back lpm_array_map[%d] after failed build: %v", mapIndex, delErr)
			}
		}
	}()

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
				m, mapErr := bpf.newLpmMap(r.keys, r.values)
				if mapErr != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("newLpmMap at index %d: %w", idx, mapErr)
					}
					mu.Unlock()
					return
				}

				// LpmArrayMap.Update is safe to call concurrently:
				// cilium/ebpf Map.Update has no internal shared mutable state
				// (map.go:280-291, all fields immutable after NewMap), and
				// each goroutine writes a distinct local LPM index from the ring
				// allocator within this slot. The syscall itself is serialized by
				// the kernel.
				// mu below only guards the firstErr aggregation.
				mapIndex := slotBase + r.lpmIndex
				mapErr = bpf.LpmArrayMap.Update(mapIndex, m, ebpf.UpdateAny)
				if mapErr != nil {
					_ = m.Close()
					mu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("update lpm_array_map[%d]: %w", mapIndex, mapErr)
					}
					mu.Unlock()
					return
				}
				installedLpmMu.Lock()
				installedLpmIndices = append(installedLpmIndices, mapIndex)
				installedLpmMu.Unlock()
				_ = m.Close()
			}(i)
		}
		wg.Wait()

		if firstErr != nil {
			return nil, firstErr
		}
	} else {
		// Serial path for small sets
		for _, r := range results {
			m, err := bpf.newLpmMap(r.keys, r.values)
			if err != nil {
				return nil, fmt.Errorf("newLpmMap: %w", err)
			}
			mapIndex := slotBase + r.lpmIndex
			if err = bpf.LpmArrayMap.Update(mapIndex, m, ebpf.UpdateAny); err != nil {
				_ = m.Close()
				return nil, fmt.Errorf("update: %w", err)
			}
			installedLpmIndices = append(installedLpmIndices, mapIndex)
			_ = m.Close()
		}
	}

	// Write routings.
	// Fallback rule MUST be the last.
	if rules[len(rules)-1].Type != uint8(consts.MatchType_Fallback) {
		return nil, fmt.Errorf("fallback rule MUST be the last")
	}
	routingsLen := uint32(len(rules))
	kernRules, err := rewriteKernRulesWithRingLpmIndex(rules, allocStartIdx, lpmCount)
	if err != nil {
		return nil, err
	}
	routingsKeys := common.ARangeU32(routingsLen)
	for i := range routingsKeys {
		routingsKeys[i] += slotBase
	}
	if bpf.RoutingMap == nil || bpf.RoutingMetaMap == nil {
		return nil, fmt.Errorf("routing maps are not initialized")
	}

	type routingMapBackup struct {
		key     uint32
		value   bpfMatchSet
		present bool
	}
	routingBackups := make([]routingMapBackup, len(routingsKeys))
	for i, key := range routingsKeys {
		var value bpfMatchSet
		lookupErr := bpf.RoutingMap.Lookup(key, &value)
		switch {
		case lookupErr == nil:
			routingBackups[i] = routingMapBackup{key: key, value: value, present: true}
		case errors.Is(lookupErr, ebpf.ErrKeyNotExist):
			routingBackups[i] = routingMapBackup{key: key}
		default:
			return nil, fmt.Errorf("snapshot routing_map[%d]: %w", key, lookupErr)
		}
	}
	var previousRoutingMeta uint32
	metaLookupErr := bpf.RoutingMetaMap.Lookup(slot, &previousRoutingMeta)
	metaPresent := metaLookupErr == nil
	if metaLookupErr != nil && !errors.Is(metaLookupErr, ebpf.ErrKeyNotExist) {
		return nil, fmt.Errorf("snapshot routing_meta_map[%d]: %w", slot, metaLookupErr)
	}

	routingWriteStarted := false
	defer func() {
		if err == nil || !routingWriteStarted {
			return
		}
		var rollbackErrs []error
		// Hide partially written rules while the old values are restored.
		if restoreErr := bpf.RoutingMetaMap.Update(slot, 0, ebpf.UpdateAny); restoreErr != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("clear routing_meta_map[%d]: %w", slot, restoreErr))
		}
		for _, backup := range routingBackups {
			if backup.present {
				if restoreErr := bpf.RoutingMap.Update(backup.key, backup.value, ebpf.UpdateAny); restoreErr != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("restore routing_map[%d]: %w", backup.key, restoreErr))
				}
				continue
			}
			if restoreErr := bpf.RoutingMap.Delete(backup.key); restoreErr != nil && !errors.Is(restoreErr, ebpf.ErrKeyNotExist) {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("delete routing_map[%d]: %w", backup.key, restoreErr))
			}
		}
		if metaPresent {
			if restoreErr := bpf.RoutingMetaMap.Update(slot, previousRoutingMeta, ebpf.UpdateAny); restoreErr != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("restore routing_meta_map[%d]: %w", slot, restoreErr))
			}
		} else if restoreErr := bpf.RoutingMetaMap.Delete(slot); restoreErr != nil && !errors.Is(restoreErr, ebpf.ErrKeyNotExist) {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("delete routing_meta_map[%d]: %w", slot, restoreErr))
		}
		if len(rollbackErrs) > 0 {
			err = errors.Join(err, errors.Join(rollbackErrs...))
		}
	}()

	routingWriteStarted = true
	if _, err = BpfMapBatchUpdate(bpf.RoutingMap, routingsKeys, kernRules, &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		return nil, fmt.Errorf("BpfMapBatchUpdate: %w", err)
	}
	if err = bpf.RoutingMetaMap.Update(slot, routingsLen, ebpf.UpdateAny); err != nil {
		return nil, fmt.Errorf("update routing_meta_map: %w", err)
	}
	log.Infof("Routing match set len: %v/%v", len(rules), consts.MaxMatchSetLen)

	// Collect all unique indices that were actually updated in the shared map.
	// Since lpmCount includes duplicates, we use results to get the mapped ring indices.
	uniqueIndices := make(map[uint32]struct{})
	for _, r := range results {
		uniqueIndices[slotBase+r.lpmIndex] = struct{}{}
	}
	usedIndices = make([]uint32, 0, len(uniqueIndices))
	for idx := range uniqueIndices {
		usedIndices = append(usedIndices, idx)
	}

	return usedIndices, nil
}

// BuildKernspaceForSlot constructs this immutable routing snapshot in one
// kernel routing epoch slot.
func (s *routingKernspaceSnapshot) BuildKernspaceForSlot(log *logrus.Logger, bpf *bpfObjects, slot uint32) (usedIndices []uint32, err error) {
	if s == nil {
		return nil, fmt.Errorf("nil routing kernspace snapshot")
	}
	return buildRoutingKernspaceForSlot(log, bpf, s.rules, s.simulatedLpmTries, s.dedupCount, slot)
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
		numWorkers := min(runtime.GOMAXPROCS(0), 8)

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
		needs:           computeRoutingMatcherNeeds(compiledMatches),
		predicateGroups: append([]routingMatcherPredicateGroupSpan(nil), b.predicateGroups...),
	}

	// Memory optimization: Release large temporary data structures
	// after building the matcher to reduce memory footprint.
	b.simulatedDomainSet = nil
	b.simulatedLpmTries = nil
	b.rules = nil
	b.compiledRules = nil
	b.predicateGroups = nil
	b.lpmDedup = nil

	return matcher, nil
}
