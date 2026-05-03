/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"fmt"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type RequestRuleCategory int

const (
	RequestRuleCategoryDNS RequestRuleCategory = iota
	RequestRuleCategorySub
	RequestRuleCategoryNode
	RequestRuleCategorySubNode
)

func SplitRequestRules(
	rules []*config_parser.RoutingRule,
) (
	dnsRules []*config_parser.RoutingRule,
	subRules []*config_parser.RoutingRule,
	nodeRules []*config_parser.RoutingRule,
	subNodeRules []*config_parser.RoutingRule,
	err error,
) {
	for _, rule := range rules {
		category, classifyErr := classifyRequestRule(rule)
		if classifyErr != nil {
			return nil, nil, nil, nil, classifyErr
		}
		switch category {
		case RequestRuleCategoryDNS:
			dnsRules = append(dnsRules, rule)
		case RequestRuleCategorySub:
			subRules = append(subRules, rule)
		case RequestRuleCategoryNode:
			nodeRules = append(nodeRules, rule)
		case RequestRuleCategorySubNode:
			subNodeRules = append(subNodeRules, rule)
		default:
			return nil, nil, nil, nil, fmt.Errorf("unknown request rule category: %v", category)
		}
	}
	return dnsRules, subRules, nodeRules, subNodeRules, nil
}

func classifyRequestRule(rule *config_parser.RoutingRule) (RequestRuleCategory, error) {
	if len(rule.AndFunctions) == 0 {
		return RequestRuleCategoryDNS, nil
	}

	var (
		internalCategory RequestRuleCategory
		hasInternal      bool
		hasDNS           bool
		otherFunction    string
	)
	for _, f := range rule.AndFunctions {
		switch f.Name {
		case consts.Function_QName, consts.Function_QType:
			if hasInternal {
				return 0, fmt.Errorf("cannot mix %q/%q with internal dae DNS selectors in one rule: %v",
					consts.Function_QName, consts.Function_QType, rule.String(false, false, false))
			}
			hasDNS = true
		case "sub":
			if hasDNS {
				return 0, fmt.Errorf("cannot mix %q/%q with internal dae DNS selectors in one rule: %v",
					consts.Function_QName, consts.Function_QType, rule.String(false, false, false))
			}
			if otherFunction != "" {
				return 0, fmt.Errorf("cannot mix internal dae DNS selectors with %q in one rule: %v", otherFunction, rule.String(false, false, false))
			}
			if !hasInternal {
				internalCategory = RequestRuleCategorySub
				hasInternal = true
			} else if internalCategory != RequestRuleCategorySub {
				return 0, fmt.Errorf("cannot mix internal dae DNS selectors in one rule: %v", rule.String(false, false, false))
			}
		case "node":
			if hasDNS {
				return 0, fmt.Errorf("cannot mix %q/%q with internal dae DNS selectors in one rule: %v",
					consts.Function_QName, consts.Function_QType, rule.String(false, false, false))
			}
			if otherFunction != "" {
				return 0, fmt.Errorf("cannot mix internal dae DNS selectors with %q in one rule: %v", otherFunction, rule.String(false, false, false))
			}
			if !hasInternal {
				internalCategory = RequestRuleCategoryNode
				hasInternal = true
			} else if internalCategory != RequestRuleCategoryNode {
				return 0, fmt.Errorf("cannot mix internal dae DNS selectors in one rule: %v", rule.String(false, false, false))
			}
		case "subnode":
			if hasDNS {
				return 0, fmt.Errorf("cannot mix %q/%q with internal dae DNS selectors in one rule: %v",
					consts.Function_QName, consts.Function_QType, rule.String(false, false, false))
			}
			if otherFunction != "" {
				return 0, fmt.Errorf("cannot mix internal dae DNS selectors with %q in one rule: %v", otherFunction, rule.String(false, false, false))
			}
			if !hasInternal {
				internalCategory = RequestRuleCategorySubNode
				hasInternal = true
			} else if internalCategory != RequestRuleCategorySubNode {
				return 0, fmt.Errorf("cannot mix internal dae DNS selectors in one rule: %v", rule.String(false, false, false))
			}
		default:
			if hasInternal {
				return 0, fmt.Errorf("cannot mix internal dae DNS selectors with %q in one rule: %v", f.Name, rule.String(false, false, false))
			}
			otherFunction = f.Name
		}
	}

	if hasInternal {
		return internalCategory, nil
	}
	return RequestRuleCategoryDNS, nil
}
