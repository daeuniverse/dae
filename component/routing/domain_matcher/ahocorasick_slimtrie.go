/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"fmt"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/trie"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/ahocorasick-domain"
)

var ValidDomainChars = trie.NewValidChars([]byte("0123456789abcdefghijklmnopqrstuvwxyz-.^_"))

type AhocorasickSlimtrie struct {
	log *logrus.Logger

	validAcIndexes     []int
	validTrieIndexes   []int
	validRegexpIndexes []int
	ac                 []*ahocorasick.Matcher
	trie               []*trie.Trie
	regexp             [][]*regexp.Regexp

	toBuildAc   [][][]byte
	toBuildTrie [][]string
	err         error

	// skippedDomains counts routing patterns that were rejected as invalid and
	// therefore never entered the trie. A rejected pattern silently changes
	// routing for every name it would have matched, so the count is
	// correctness information, not a log-volume detail: the first rejection is
	// reported with its offending character and the per-call total is reported
	// in one aggregate line.
	skippedDomains uint64

	// matchCache memoizes the most recent qname resolutions. A single DNS
	// query otherwise recomputes the same domain bitmap up to six times
	// (request select, response select, and once per ip-version x protocol
	// dialer iteration). Capacity-bounded, scan on overflow.
	matchMu       sync.RWMutex
	matchCache    map[string][]uint32
	matchCacheOrd []string
}

func NewAhocorasickSlimtrie(log *logrus.Logger, bitLength int) *AhocorasickSlimtrie {
	return &AhocorasickSlimtrie{
		log:         log,
		ac:          make([]*ahocorasick.Matcher, bitLength),
		trie:        make([]*trie.Trie, bitLength),
		regexp:      make([][]*regexp.Regexp, bitLength),
		toBuildAc:   make([][][]byte, bitLength),
		toBuildTrie: make([][]string, bitLength),
	}
}
func (n *AhocorasickSlimtrie) AddSet(bitIndex int, patterns []string, typ consts.RoutingDomainKey) {
	if n.err != nil {
		return
	}
	// Rule indices come from len(builder.rules) and index the per-rule slices
	// allocated with bitLength (= consts.MaxMatchSetLen). An out-of-range
	// index would panic on the slice writes below; record it as a build error
	// so oversized configurations fail with a message instead of crashing.
	if bitIndex < 0 || bitIndex >= len(n.toBuildTrie) {
		n.err = fmt.Errorf("domain rule index %d is out of range [0, %d): too many routing rules", bitIndex, len(n.toBuildTrie))
		return
	}
	// Pre-grow slices to avoid repeated growslice when appending many patterns.
	maxTrieEntries := 0
	maxAcEntries := 0
	switch typ {
	case consts.RoutingDomainKey_Full:
		maxTrieEntries = len(patterns)
	case consts.RoutingDomainKey_Suffix:
		maxTrieEntries = len(patterns) * 2
	case consts.RoutingDomainKey_Keyword:
		maxAcEntries = len(patterns)
	}
	if maxTrieEntries > 0 {
		n.toBuildTrie[bitIndex] = slices.Grow(n.toBuildTrie[bitIndex], maxTrieEntries)
	}
	if maxAcEntries > 0 {
		n.toBuildAc[bitIndex] = slices.Grow(n.toBuildAc[bitIndex], maxAcEntries)
	}
	skippedInThisSet := uint64(0)
nextPattern:
	for _, d := range patterns {
		switch typ {
		case consts.RoutingDomainKey_Full,
			consts.RoutingDomainKey_Suffix,
			consts.RoutingDomainKey_Keyword:
			// DNS names are case-insensitive, matching the normalization used
			// by MatchDomainBitmap. Regex patterns keep their original case.
			d = strings.ToLower(d)
		}
		switch typ {
		case consts.RoutingDomainKey_Full:
			for _, r := range []byte(d) {
				if !ValidDomainChars.IsValidChar(r) {
					skippedInThisSet++
					n.noteSkippedDomain("full", bitIndex, d, r)
					continue nextPattern
				}
			}
			n.toBuildTrie[bitIndex] = append(n.toBuildTrie[bitIndex], "^"+d+"$")
		case consts.RoutingDomainKey_Suffix:
			for _, r := range []byte(d) {
				if !ValidDomainChars.IsValidChar(r) {
					skippedInThisSet++
					n.noteSkippedDomain("suffix", bitIndex, d, r)
					continue nextPattern
				}
			}
			if strings.HasPrefix(d, ".") {
				// abc.example.com
				n.toBuildTrie[bitIndex] = append(n.toBuildTrie[bitIndex], d+"$")
				// cannot match example.com
			} else {
				// xxx.example.com
				n.toBuildTrie[bitIndex] = append(n.toBuildTrie[bitIndex], "."+d+"$")
				// example.com
				n.toBuildTrie[bitIndex] = append(n.toBuildTrie[bitIndex], "^"+d+"$")
				// cannot match abcexample.com
			}
		case consts.RoutingDomainKey_Keyword:
			// Only use ac automaton for "keyword" matching to save memory.
			n.toBuildAc[bitIndex] = append(n.toBuildAc[bitIndex], []byte(d))
		case consts.RoutingDomainKey_Regex:
			r, err := regexp.Compile(d)
			if err != nil {
				n.err = fmt.Errorf("failed to compile regex: %v", d)
				return
			}
			n.regexp[bitIndex] = append(n.regexp[bitIndex], r)
		default:
			n.err = fmt.Errorf("unknown RoutingDomainKey: %v", typ)
			return
		}
	}
	n.logSkippedDomainSummary(bitIndex, typ, skippedInThisSet)
}

// noteSkippedDomain records one routing pattern rejected as invalid. The first
// rejection is a warning with its offending character (so the user can fix the
// rule); every later one keeps its detail at debug. Either way the pattern
// never enters the trie, so routing silently changes for the names it would
// have matched — the count below is what keeps that visible.
func (n *AhocorasickSlimtrie) noteSkippedDomain(kind string, bitIndex int, domain string, offending byte) {
	n.skippedDomains++
	skipped := n.skippedDomains
	if n.log == nil {
		return
	}
	if skipped == 1 {
		n.log.WithFields(logrus.Fields{
			"rule_index": bitIndex,
			"domain":     domain,
			"char":       string(offending),
			"key_type":   kind,
			"total":      skipped,
		}).Warnf("DomainMatcher: bad %v domain rejected and NOT applied to routing (unexpected char %q); later rejections are reported at debug and counted in the per-rule summary",
			kind, string(offending))
		return
	}
	n.log.WithFields(logrus.Fields{
		"rule_index": bitIndex,
		"domain":     domain,
		"char":       string(offending),
		"key_type":   kind,
		"total":      skipped,
	}).Debugf("DomainMatcher: bad %v domain rejected and NOT applied to routing", kind)
}

// logSkippedDomainSummary emits the one line that closes an AddSet call when
// patterns were dropped, so a rule that loses many patterns is one warning
// plus this count instead of one warning per pattern. total_skipped keeps the
// lifetime magnitude visible across rules and reloads.
func (n *AhocorasickSlimtrie) logSkippedDomainSummary(bitIndex int, typ consts.RoutingDomainKey, skipped uint64) {
	if skipped == 0 || n.log == nil {
		return
	}
	n.log.WithFields(logrus.Fields{
		"rule_index":    bitIndex,
		"key_type":      string(typ),
		"skipped":       skipped,
		"total_skipped": n.skippedDomains,
	}).Warnf("DomainMatcher: %d pattern(s) of this rule were rejected and are NOT used for routing; routing decisions for the names they would match are unaffected by this rule",
		skipped)
}

// SkippedDomainCount reports how many routing patterns were rejected as
// invalid across this matcher's lifetime.
func (n *AhocorasickSlimtrie) SkippedDomainCount() uint64 {
	if n == nil {
		return 0
	}
	return n.skippedDomains
}

// matchCacheCap bounds the per-matcher qname->bitmap memo (small: sequential
// DNS traffic has high temporal locality).
const matchCacheCap = 512

// MatchDomainBitmap returns the routing bitmap for domain. The returned
// slice is immutable and may alias the memo; callers must not write it
// in place (an in-place OR would poison every later DnsCache lookup).
// The hit path does not clone: that would undo the memo.
func (n *AhocorasickSlimtrie) MatchDomainBitmap(domain string) (bitmap []uint32) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	// Hit path takes only a read lock: concurrent flow establishments must
	// not serialize behind this cache (that regressed CPU once already).
	n.matchMu.RLock()
	if cached, ok := n.matchCache[domain]; ok {
		n.matchMu.RUnlock()
		return cached
	}
	n.matchMu.RUnlock()

	bitmap = n.matchDomainBitmapUncached(domain)

	// Insert under the write lock; a concurrent builder of the same domain
	// (stampede) kept its own result, last writer wins, values are identical.
	n.matchMu.Lock()
	if n.matchCache == nil {
		n.matchCache = make(map[string][]uint32, 64)
	}
	if _, exists := n.matchCache[domain]; !exists {
		if len(n.matchCacheOrd) >= matchCacheCap {
			evict := n.matchCacheOrd[0]
			n.matchCacheOrd = n.matchCacheOrd[1:]
			delete(n.matchCache, evict)
		}
		n.matchCache[domain] = bitmap
		n.matchCacheOrd = append(n.matchCacheOrd, domain)
	}
	n.matchMu.Unlock()
	return bitmap
}

func (n *AhocorasickSlimtrie) matchDomainBitmapUncached(domain string) (bitmap []uint32) {
	N := len(n.ac) / 32
	if len(n.ac)%32 != 0 {
		N++
	}
	bitmap = make([]uint32, N)
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	// Domain should consist of 'a'-'z' and '.' and '-'
	// NOTE: DO NOT VERIFY THE DOMAIN TO MATCH: https://github.com/daeuniverse/dae/issues/528
	// for _, b := range []byte(domain) {
	// 	if !ahocorasick.IsValidChar(b) {
	// 		return bitmap
	// 	}
	// }
	// Suffix matching.
	suffixTrieDomain := ToSuffixTrieString("^" + domain)
	for _, i := range n.validTrieIndexes {
		if bitmap[i/32]&(1<<(i%32)) > 0 {
			// Already matched.
			continue
		}
		if n.trie[i].HasPrefix(suffixTrieDomain) {
			bitmap[i/32] |= 1 << (i % 32)
		}
	}
	// Keyword matching.
	// Add magic chars as head and tail.
	acDomain := "^" + domain + "$"
	for _, i := range n.validAcIndexes {
		if bitmap[i/32]&(1<<(i%32)) > 0 {
			// Already matched.
			continue
		}
		if n.ac[i].Contains([]byte(acDomain)) {
			bitmap[i/32] |= 1 << (i % 32)
		}
	}
	// Regex matching.
	for _, i := range n.validRegexpIndexes {
		if bitmap[i/32]&(1<<(i%32)) > 0 {
			// Already matched.
			continue
		}
		for _, r := range n.regexp[i] {
			if r.MatchString(domain) {
				bitmap[i/32] |= 1 << (i % 32)
				break
			}
		}
	}
	return bitmap
}
func ToSuffixTrieString(s string) string {
	// No need for end char "$".
	b := []byte(strings.TrimSuffix(s, "$"))
	// Reverse.
	half := len(b) / 2
	for i := range half {
		b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
	}
	return string(b)
}
func ToSuffixTrieStrings(s []string) []string {
	to := make([]string, len(s))
	for i := range s {
		to[i] = ToSuffixTrieString(s[i])
	}
	return to
}
func (n *AhocorasickSlimtrie) Build() (err error) {
	n.matchMu.Lock()
	n.matchCache = nil
	n.matchCacheOrd = nil
	n.matchMu.Unlock()

	if n.err != nil {
		return n.err
	}
	n.validAcIndexes = make([]int, 0, len(n.toBuildAc)/8)
	n.validTrieIndexes = make([]int, 0, len(n.toBuildAc)/8)
	n.validRegexpIndexes = make([]int, 0, len(n.toBuildAc)/8)

	// Build AC automaton and trie in parallel for better performance.
	// Use limited concurrency to avoid overwhelming the system.
	numWorkers := min(
		runtime.GOMAXPROCS(0),
		4, // Limit to 4 workers to balance performance and memory
	)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var buildErr error

	// Build AC automaton in parallel.
	wg.Go(func() {
		sem := make(chan struct{}, numWorkers)
		var innerWg sync.WaitGroup
		for i, toBuild := range n.toBuildAc {
			if len(toBuild) == 0 {
				continue
			}
			innerWg.Add(1)
			sem <- struct{}{}
			go func(idx int, patterns [][]byte) {
				defer func() { <-sem }()
				defer innerWg.Done()
				matcher, err := ahocorasick.NewMatcher(patterns)
				if err != nil {
					mu.Lock()
					if buildErr == nil {
						buildErr = err
					}
					mu.Unlock()
					return
				}
				mu.Lock()
				n.ac[idx] = matcher
				n.validAcIndexes = append(n.validAcIndexes, idx)
				mu.Unlock()
			}(i, toBuild)
		}
		innerWg.Wait()
	})

	// Build succinct trie in parallel.
	wg.Go(func() {
		sem := make(chan struct{}, numWorkers)
		var innerWg sync.WaitGroup
		for i, toBuild := range n.toBuildTrie {
			if len(toBuild) == 0 {
				continue
			}
			innerWg.Add(1)
			sem <- struct{}{}
			go func(idx int, patterns []string) {
				defer func() { <-sem }()
				defer innerWg.Done()
				transformed := ToSuffixTrieStrings(patterns)
				t, err := trie.NewTrie(transformed, ValidDomainChars)
				if err != nil {
					mu.Lock()
					if buildErr == nil {
						buildErr = err
					}
					mu.Unlock()
					return
				}
				mu.Lock()
				n.trie[idx] = t
				n.validTrieIndexes = append(n.validTrieIndexes, idx)
				mu.Unlock()
			}(i, toBuild)
		}
		innerWg.Wait()
	})

	wg.Wait()

	if buildErr != nil {
		return buildErr
	}

	// Regexp - already compiled during AddSet, just collect indexes.
	for i := range n.regexp {
		if len(n.regexp[i]) == 0 {
			continue
		}
		n.validRegexpIndexes = append(n.validRegexpIndexes, i)
	}

	// Release unused data.
	n.toBuildAc = nil
	n.toBuildTrie = nil

	// Reclaim temporary build allocations (BFS queues, transformed string
	// slices) immediately so peak memory does not linger into steady state.
	runtime.GC()
	return nil
}
