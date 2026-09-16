/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"fmt"
	"maps"
	"sort"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/dlclark/regexp2"
	"github.com/sirupsen/logrus"
)

var regexpCache sync.Map

// ResetRegexpCacheForReload drops the compiled-filter cache.
//
// The keys are the regex literals of the configured group filters, so entries
// can only accumulate across in-process reloads: without this, the map's
// membership is the union of every config the process has ever loaded rather
// than the live config, and the process never gives that memory back. dae keeps
// the rest of its process-global proxy state on the same footing (see
// dialer.ResetGlobalProxyStateForReload, called from the reload worker
// alongside this).
//
// Rebuilding costs one regexp2 compile per distinct pattern still in use, which
// is the work the first evaluation of that pattern would have done anyway, so
// no result changes.
func ResetRegexpCacheForReload() {
	regexpCache.Range(func(key, _ any) bool {
		regexpCache.Delete(key)
		return true
	})
}

const (
	FilterInput_Name            = "name"
	FilterInput_SubscriptionTag = "subtag"
)

const (
	FilterKey_Name_Regex   = "regex"
	FilterKey_Name_Keyword = "keyword"

	FilterInput_SubscriptionTag_Regex = "regex"
)

type DialerSet struct {
	log          *logrus.Logger
	dialers      []*dialer.Dialer
	nodeToTagMap map[*dialer.Dialer]string

	// parseFailures counts nodes that were dropped because their link could
	// not be parsed into a dialer. They are not routable, so the count is a
	// correctness signal for the operator, not just noise control; it is also
	// what the aggregate line reports after a subscription refresh that
	// produced many bad nodes at once. The counter is cumulative for the set's
	// lifetime; parseFailuresReported remembers how much of it the last
	// summary already covered.
	parseFailuresMu       sync.Mutex
	parseFailures         uint64
	parseFailuresReported uint64
	parseFailuresBy       map[string]uint64
}

// AllDialers returns a snapshot of every dialer owned by the set.
func (s *DialerSet) AllDialers() []*dialer.Dialer {
	if s == nil {
		return nil
	}
	return append([]*dialer.Dialer(nil), s.dialers...)
}

// noteParseFailure records one dropped node. The first dropped node of the
// build warns with the concrete parse error; the rest are folded into a single
// aggregate line, because a subscription refresh can invalidate hundreds of
// nodes at once and one warning per node would both flood the log and hide the
// total, which is the number that matters.
func (s *DialerSet) noteParseFailure(subscriptionTag string, err error) {
	if s == nil {
		return
	}
	s.parseFailuresMu.Lock()
	s.parseFailures++
	total := s.parseFailures
	first := total == 1
	if s.parseFailuresBy == nil {
		s.parseFailuresBy = make(map[string]uint64)
	}
	s.parseFailuresBy[subscriptionTag]++
	s.parseFailuresMu.Unlock()

	if s.log == nil {
		return
	}
	if first {
		s.log.WithFields(logrus.Fields{
			"subscription": subscriptionTag,
			"total":        total,
		}).Warnf("failed to parse node: %v; the node is dropped and will not participate in routing", err)
		return
	}
	// Every later failure keeps its own cause and subscription tag at debug so
	// a mixed batch stays diagnosable without one line per node.
	s.log.WithFields(logrus.Fields{
		"subscription": subscriptionTag,
		"total":        total,
	}).Debugf("failed to parse node: %v", err)
}

// logParseFailureSummary emits the one line that closes a batch of dropped
// nodes. It reports the number of nodes dropped since the last summary, so a
// later refresh reports its own total.
func (s *DialerSet) logParseFailureSummary() {
	if s == nil || s.log == nil {
		return
	}
	s.parseFailuresMu.Lock()
	total := s.parseFailures
	batch := total - s.parseFailuresReported
	s.parseFailuresReported = total
	byTag := make(map[string]uint64, len(s.parseFailuresBy))
	maps.Copy(byTag, s.parseFailuresBy)
	s.parseFailuresBy = nil
	s.parseFailuresMu.Unlock()
	if batch == 0 {
		return
	}
	tags := make([]string, 0, len(byTag))
	for tag := range byTag {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	parts := make([]string, 0, len(tags))
	for _, tag := range tags {
		parts = append(parts, fmt.Sprintf("%s=%d", tag, byTag[tag]))
	}
	s.log.Warnf("%d node(s) were skipped because their link could not be parsed and do not participate in routing (by subscription: %s; total skipped since start: %d)",
		batch, strings.Join(parts, ", "), total)
}

func NewDialerSetFromLinksContext(ctx context.Context, option *dialer.GlobalOption, tagToNodeList map[string][]string) *DialerSet {
	s := &DialerSet{
		log:          option.Log,
		dialers:      make([]*dialer.Dialer, 0),
		nodeToTagMap: make(map[*dialer.Dialer]string),
	}
	for subscriptionTag, nodes := range tagToNodeList {
		for _, node := range nodes {
			d, err := dialer.NewFromLinkContext(ctx, option, dialer.InstanceOption{DisableCheck: false}, node, subscriptionTag)
			if err != nil {
				s.noteParseFailure(subscriptionTag, err)
				continue
			}
			s.dialers = append(s.dialers, d)
			s.nodeToTagMap[d] = subscriptionTag
		}
	}
	s.logParseFailureSummary()
	return s
}

func (s *DialerSet) filterHit(dialer *dialer.Dialer, filters []*config_parser.Function) (hit bool, err error) {
	if len(filters) == 0 {
		// No filter.
		return true, nil
	}

	// Example
	// filter: name(regex:'^.*hk.*$', keyword:'sg') && name(keyword:'disney')
	// filter: !name(regex: 'HK|TW|SG') && name(keyword: disney)
	// filter: subtag(my_sub, regex:^my_, regex:my_)

	// And
	for _, filter := range filters {
		var subFilterHit bool

		switch filter.Name {
		case FilterInput_Name:
			// Or
		loop:
			for _, param := range filter.Params {
				switch param.Key {
				case FilterKey_Name_Regex:
					re, ok := regexpCache.Load(param.Val)
					var regex *regexp2.Regexp
					if !ok {
						var err error
						regex, err = regexp2.Compile(param.Val, 0)
						if err != nil {
							return false, fmt.Errorf("bad regexp in filter %v: %w", filter.String(false, true, true), err)
						}
						regexpCache.Store(param.Val, regex)
					} else {
						regex = re.(*regexp2.Regexp)
					}
					matched, _ := regex.MatchString(dialer.Property().Name)
					// logrus.Warnln(param.Val, matched, dialer.Name())
					if matched {
						subFilterHit = true
						break loop
					}
				case FilterKey_Name_Keyword:
					if strings.Contains(dialer.Property().Name, param.Val) {
						subFilterHit = true
						break loop
					}
				case "":
					if dialer.Property().Name == param.Val {
						subFilterHit = true
						break loop
					}
				default:
					return false, fmt.Errorf(`unsupported filter key "%v" in "filter: %v()"`, param.Key, filter.Name)
				}
			}
		case FilterInput_SubscriptionTag:
			// Or
		loop2:
			for _, param := range filter.Params {
				switch param.Key {
				case FilterInput_SubscriptionTag_Regex:
					re, ok := regexpCache.Load(param.Val)
					var regex *regexp2.Regexp
					if !ok {
						var err error
						regex, err = regexp2.Compile(param.Val, 0)
						if err != nil {
							return false, fmt.Errorf("bad regexp in filter %v: %w", filter.String(false, true, true), err)
						}
						regexpCache.Store(param.Val, regex)
					} else {
						regex = re.(*regexp2.Regexp)
					}
					matched, _ := regex.MatchString(s.nodeToTagMap[dialer])
					if matched {
						subFilterHit = true
						break loop2
					}
					// logrus.Warnln(param.Val, matched, dialer.Name())
				case "":
					// Full
					if s.nodeToTagMap[dialer] == param.Val {
						subFilterHit = true
						break loop2
					}
				default:
					return false, fmt.Errorf(`unsupported filter key "%v" in "filter: %v()"`, param.Key, filter.Name)
				}
			}

		default:
			return false, fmt.Errorf(`unsupported filter input type: "%v"`, filter.Name)
		}

		if subFilterHit == filter.Not {
			return false, nil
		}
	}
	return true, nil
}

func (s *DialerSet) FilterAndAnnotate(filters [][]*config_parser.Function, annotations [][]*config_parser.Param) (dialers []*dialer.Dialer, filterAnnotations []*dialer.Annotation, err error) {
	if len(filters) != len(annotations) {
		return nil, nil, fmt.Errorf("[CODE BUG]: unmatched annotations length: %v filters and %v annotations", len(filters), len(annotations))
	}
	if len(filters) == 0 {
		anno := make([]*dialer.Annotation, len(s.dialers))
		for i := range anno {
			anno[i] = &dialer.Annotation{}
		}
		return s.dialers, anno, nil
	}
nextDialerLoop:
	for _, d := range s.dialers {
		// Hit any.
		for j, f := range filters {
			hit, err := s.filterHit(d, f)
			if err != nil {
				return nil, nil, err
			}
			if hit {
				anno, err := dialer.NewAnnotation(annotations[j])
				if err != nil {
					return nil, nil, fmt.Errorf("apply filter annotation: %w", err)
				}
				dialers = append(dialers, d)
				filterAnnotations = append(filterAnnotations, anno)
				continue nextDialerLoop
			}
		}
	}
	return dialers, filterAnnotations, nil
}

func (s *DialerSet) Close() error {
	var err error
	for _, d := range s.dialers {
		if e := d.Close(); e != nil {
			err = e
		}
	}
	return err
}
