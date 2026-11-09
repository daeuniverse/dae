/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// DnsRuleSnapshot is one rendered DNS routing rule.
type DnsRuleSnapshot struct {
	Expression string
	Action     string
	Upstream   string
}

// DnsRulesSnapshot is the complete DNS request/response rule dictionary.
type DnsRulesSnapshot struct {
	GenerationID     string
	Request          []DnsRuleSnapshot
	RequestFallback  DnsRuleSnapshot
	Response         []DnsRuleSnapshot
	ResponseFallback DnsRuleSnapshot
}

// MaximumDnsRuleDictionarySize bounds the advertised DNS rule capacity.
const MaximumDnsRuleDictionarySize = 1 << 16

func dnsRulesFromConfig(routing *config.DnsRouting, generation string) DnsRulesSnapshot {
	snapshot := DnsRulesSnapshot{GenerationID: generation}
	if routing == nil {
		return snapshot
	}
	snapshot.Request = renderDnsRuleList(routing.Request.Rules)
	snapshot.Response = renderDnsRuleList(routing.Response.Rules)
	snapshot.RequestFallback = renderDnsFunction(routing.Request.Fallback)
	snapshot.ResponseFallback = renderDnsFunction(routing.Response.Fallback)
	return snapshot
}

func renderDnsRuleList(rules []*config_parser.RoutingRule) []DnsRuleSnapshot {
	result := make([]DnsRuleSnapshot, 0, len(rules))
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		snapshot := DnsRuleSnapshot{
			Expression: rule.String(false, false, false),
			Action:     rule.Outbound.Name,
		}
		if len(rule.Outbound.Params) > 0 {
			snapshot.Upstream = rule.Outbound.Params[0].String(false, true)
		}
		result = append(result, snapshot)
	}
	return result
}

func renderDnsFunction(value config.FunctionOrString) DnsRuleSnapshot {
	function, err := config.ParseFunctionOrString(value)
	if err != nil || function == nil {
		return DnsRuleSnapshot{}
	}
	snapshot := DnsRuleSnapshot{
		Expression: function.MarshalString(false, false, true),
		Action:     function.Name,
	}
	if len(function.Params) > 0 {
		snapshot.Upstream = function.Params[0].String(false, true)
	}
	return snapshot
}

// SnapshotDnsRules projects this generation's DNS rule dictionary.
func (c *ControlPlane) SnapshotDnsRules() DnsRulesSnapshot {
	if c == nil {
		return DnsRulesSnapshot{}
	}
	return DnsRulesSnapshot{
		GenerationID:     c.dnsRules.GenerationID,
		Request:          append([]DnsRuleSnapshot(nil), c.dnsRules.Request...),
		RequestFallback:  c.dnsRules.RequestFallback,
		Response:         append([]DnsRuleSnapshot(nil), c.dnsRules.Response...),
		ResponseFallback: c.dnsRules.ResponseFallback,
	}
}
