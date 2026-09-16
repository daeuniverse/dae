/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// SniffPuntInjection reports one implicit sniff-punt rule injected by
// InferSniffPunt so reload logs can name what was added on the user's behalf.
type SniffPuntInjection struct {
	// Selector is the rendered selector function of the injected rule,
	// e.g. mac('aa:bb:cc:dd:ee:ff').
	Selector string

	// FallbackRuleIndex is the 1-based index, in the original rule list, of
	// the selector-only direct-class rule the punt rule was inserted before.
	FallbackRuleIndex int
}

// sniffPuntSelector is a single-host device selector (mac or sip) extracted
// from a whitelist/fallback rule pair. Values are normalized (lowercase mac,
// single-host prefix for sip), deduplicated and sorted so intersections and
// dedup keys are stable.
type sniffPuntSelector struct {
	fn     string
	values []string
}

func (s *sniffPuntSelector) dedupeKey() string {
	return s.fn + "|" + strings.Join(s.values, ",")
}

func (s *sniffPuntSelector) puntFunction() *config_parser.Function {
	params := make([]*config_parser.Param, 0, len(s.values))
	for _, v := range s.values {
		params = append(params, &config_parser.Param{Key: "", Val: sniffPuntDisplayValue(v)})
	}
	return &config_parser.Function{Name: s.fn, Params: params}
}

func sniffPuntDisplayValue(v string) string {
	// sip values are stored masked as single-host prefixes; the routing
	// grammar spells bare hosts without the redundant /32 or /128.
	if strings.HasSuffix(v, "/32") || strings.HasSuffix(v, "/128") {
		return strings.SplitN(v, "/", 2)[0]
	}
	return v
}

// isSniffPuntReservedOutbound reports whether the outbound name is one of the
// reserved routing outbounds that cannot act as a proxy whitelist target.
func isSniffPuntReservedOutbound(name string) bool {
	switch name {
	case consts.OutboundDirect.String(),
		consts.OutboundBlock.String(),
		consts.OutboundMustRules.String(),
		consts.OutboundControlPlaneRouting.String():
		return true
	}
	return false
}

// parseSniffPuntSelector validates and normalizes a selector function. Named
// parameters (geoip:-style) and negation disqualify the selector: punt
// inference only covers single-host device selectors.
func parseSniffPuntSelector(f *config_parser.Function) *sniffPuntSelector {
	if f.Not || len(f.Params) == 0 {
		return nil
	}
	values := make([]string, 0, len(f.Params))
	for _, p := range f.Params {
		if p.Key != "" {
			return nil
		}
		switch f.Name {
		case consts.Function_Mac:
			// Value syntax is validated by the mac parser at lowering time;
			// only case-insensitive identity matters for inference.
			values = append(values, strings.ToLower(p.Val))
		case consts.Function_SourceIp:
			prefix, err := parseSniffPuntSingleHost(p.Val)
			if err != nil {
				return nil
			}
			values = append(values, prefix)
		default:
			return nil
		}
	}
	sort.Strings(values)
	values = values[:dedupeSorted(values)]
	if len(values) == 0 {
		return nil
	}
	return &sniffPuntSelector{fn: f.Name, values: values}
}

func parseSniffPuntSingleHost(v string) (string, error) {
	if prefix, err := netip.ParsePrefix(v); err == nil {
		if prefix.Bits() != prefix.Addr().BitLen() {
			return "", fmt.Errorf("not a single-host prefix: %v", v)
		}
		return prefix.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(v)
	if err != nil {
		return "", err
	}
	return netip.PrefixFrom(addr, addr.BitLen()).String(), nil
}

func dedupeSorted(sorted []string) int {
	out := 0
	for i, v := range sorted {
		if i == 0 || v != sorted[out-1] {
			sorted[out] = v
			out++
		}
	}
	return out
}

// sniffPuntWhitelist recognizes the whitelist half of the shape:
//
//	selector && domain(...) -> <user group>
//
// with every condition positive. Returns nil when the rule does not have the
// shape. Negated domain conditions are refused on purpose: on an
// unknown-destination the kernel-space bitmap is empty, so !domain(...) is
// vacuously true and the rule already wins before any punt could help.
func sniffPuntWhitelist(rule *config_parser.RoutingRule) *sniffPuntSelector {
	if isSniffPuntReservedOutbound(rule.Outbound.Name) {
		return nil
	}
	var sel *sniffPuntSelector
	hasDomain := false
	for _, f := range rule.AndFunctions {
		switch f.Name {
		case consts.Function_Mac, consts.Function_SourceIp:
			if sel != nil {
				return nil
			}
			sel = parseSniffPuntSelector(f)
			if sel == nil {
				return nil
			}
		case consts.Function_Domain:
			if f.Not {
				return nil
			}
			hasDomain = true
		default:
			// Conservative: conditions beyond the selector and the domain
			// half (dport, pname, ...) are outside v1 inference.
			return nil
		}
	}
	if sel == nil || !hasDomain {
		return nil
	}
	return sel
}

// sniffPuntFallbackValues recognizes the swallow half of the shape: a later
// selector-only rule with a domain-independent decision (direct or block).
// It returns the rule's normalized selector values.
func sniffPuntFallbackValues(rule *config_parser.RoutingRule, fn string) (map[string]struct{}, bool) {
	switch rule.Outbound.Name {
	case consts.OutboundDirect.String(), consts.OutboundBlock.String():
	default:
		return nil, false
	}
	if len(rule.AndFunctions) != 1 {
		return nil, false
	}
	sel := parseSniffPuntSelector(rule.AndFunctions[0])
	if sel == nil || sel.fn != fn {
		return nil, false
	}
	values := make(map[string]struct{}, len(sel.values))
	for _, v := range sel.values {
		values[v] = struct{}{}
	}
	return values, true
}

// InferSniffPunt inspects normalized routing rules for device-scoped
// whitelist shapes whose domain half silently dies when the client's DNS
// bypasses dae: without a domain bitmap in kernel space, every connection of
// the device falls through the whitelist to the selector-only fallback.
//
// For each shape it inserts an implicit kernel-space-only
//
//	selector -> <control plane routing>
//
// line before the closest later selector-only fallback with an overlapping
// selector. Punted connections are sniffed userspace-side and re-routed over
// the full rule set with the sniffed domain, so the whitelist applies even
// without DNS knowledge; non-whitelisted traffic still lands on the fallback.
// Everything else in the rule list is untouched, and the returned slice
// preserves the original order and indices except for the insertions.
func InferSniffPunt(rules []*config_parser.RoutingRule) ([]*config_parser.RoutingRule, []SniffPuntInjection) {
	type insertion struct {
		before int
		rule   *config_parser.RoutingRule
		inj    SniffPuntInjection
	}
	var (
		insertions []insertion
		seen       = make(map[string]struct{})
	)
	for i, rule := range rules {
		sel := sniffPuntWhitelist(rule)
		if sel == nil {
			continue
		}
		for j := i + 1; j < len(rules); j++ {
			fbValues, ok := sniffPuntFallbackValues(rules[j], sel.fn)
			if !ok {
				continue
			}
			merged := intersectSniffPuntSelector(sel, fbValues)
			if merged == nil {
				// Fallback for a disjoint selector of the same type; keep
				// scanning for one that actually swallows this whitelist.
				continue
			}
			key := merged.dedupeKey()
			if _, dup := seen[key]; dup {
				break
			}
			seen[key] = struct{}{}
			puntFn := merged.puntFunction()
			insertions = append(insertions, insertion{
				before: j,
				rule: &config_parser.RoutingRule{
					AndFunctions: []*config_parser.Function{puntFn},
					Outbound:     config_parser.Function{Name: consts.OutboundControlPlaneRouting.String()},
				},
				inj: SniffPuntInjection{
					Selector:          puntFn.String(false, true, false),
					FallbackRuleIndex: j + 1,
				},
			})
			break
		}
	}
	if len(insertions) == 0 {
		return rules, nil
	}
	sort.SliceStable(insertions, func(a, b int) bool {
		return insertions[a].before < insertions[b].before
	})
	out := make([]*config_parser.RoutingRule, 0, len(rules)+len(insertions))
	injList := make([]SniffPuntInjection, 0, len(insertions))
	next := 0
	for idx, rule := range rules {
		for next < len(insertions) && insertions[next].before == idx {
			out = append(out, insertions[next].rule)
			injList = append(injList, insertions[next].inj)
			next++
		}
		out = append(out, rule)
	}
	return out, injList
}

func intersectSniffPuntSelector(sel *sniffPuntSelector, fallbackValues map[string]struct{}) *sniffPuntSelector {
	var merged []string
	for _, v := range sel.values {
		if _, ok := fallbackValues[v]; ok {
			merged = append(merged, v)
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return &sniffPuntSelector{fn: sel.fn, values: merged}
}
