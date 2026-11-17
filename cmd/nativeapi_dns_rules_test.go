/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"testing"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/control"
)

func TestNativeDnsActionNamesTheUpstream(t *testing.T) {
	// A request rule that names an upstream sends the query there. Reporting
	// "asis" claimed it went to the original destination instead.
	tests := []struct {
		kind      string
		action    string
		upstream  string
		wantKind  string
		wantUpstr string
	}{
		{"request", "alidns", "", "upstream", "alidns"},
		{"request", "asis", "", "asis", ""},
		{"request", "reject", "", "reject", ""},
		{"request", "upstream", "googledns", "upstream", "googledns"},
		{"response", "accept", "", "accept", ""},
		{"response", "requery", "alidns", "requery", "alidns"},
	}
	for _, test := range tests {
		kind := nativeDnsAction(test.kind, test.action)
		if kind != test.wantKind {
			t.Fatalf("nativeDnsAction(%q, %q) = %q, want %q", test.kind, test.action, kind, test.wantKind)
		}
		upstream := nativeDnsUpstreamOf(kind, test.action, test.upstream)
		got := ""
		if upstream != nil {
			got = *upstream
		}
		if got != test.wantUpstr {
			t.Fatalf("nativeDnsUpstreamOf(%q, %q, %q) = %q, want %q", kind, test.action, test.upstream, got, test.wantUpstr)
		}
	}
}

func TestNativeDnsRulesProjectConfiguredForm(t *testing.T) {
	rules := []control.DnsRuleSnapshot{
		{Expression: "qname(geosite:cn) -> alidns", Action: "alidns"},
		{Expression: "qtype(aaaa) -> reject", Action: "reject"},
	}
	fallback := control.DnsRuleSnapshot{Expression: "fallback: googledns", Action: "googledns"}
	projected := nativeDnsRules("request", rules, fallback)
	if len(projected) != 3 {
		t.Fatalf("len = %d, want 2 rules and 1 fallback", len(projected))
	}
	// The contract requires upstream whenever the action is upstream, so a
	// projection that dropped the name would fail schema validation.
	if projected[0].Action != "upstream" || projected[0].Upstream == nil || *projected[0].Upstream != "alidns" {
		t.Fatalf("first rule = %+v, want action upstream with upstream alidns", projected[0])
	}
	if projected[1].Action != "reject" || projected[1].Upstream != nil {
		t.Fatalf("second rule = %+v, want reject with a null upstream", projected[1])
	}
	if projected[2].Kind != "fallback" || projected[2].Upstream == nil || *projected[2].Upstream != "googledns" {
		t.Fatalf("fallback = %+v, want the configured upstream", projected[2])
	}
}

func TestDnsLogSrcMatchesIPLiteral(t *testing.T) {
	// The log records the client as address:port; the contract filter is an IP
	// literal, so comparing the strings directly never matched.
	if !dnsLogSrcMatches("192.0.2.10:51234", "192.0.2.10") {
		t.Fatal("an address:port record must match its IP literal")
	}
	if dnsLogSrcMatches("192.0.2.11:51234", "192.0.2.10") {
		t.Fatal("a different client address must not match")
	}
}

func TestFlowSummaryCarriesConnectionID(t *testing.T) {
	// The contract requires connection_id on a flow summary and defines the
	// filter as an exact match over active and retained flows.
	flow := control.SessionFlowHistoryEntry{}
	flow.ID = "f_abc"
	summary := nativeFlowSummary(flow, "instance-1")
	if summary.ConnectionID == nil || *summary.ConnectionID != connectionIDOfFlow(flow.ID) {
		t.Fatalf("connection_id = %v, want %q", summary.ConnectionID, connectionIDOfFlow(flow.ID))
	}
	if summary.ID != flow.ID {
		t.Fatalf("flow id = %q, want %q", summary.ID, flow.ID)
	}
	_ = nativeapi.FlowSummary{}
}

func TestDnsLogNameFilterMatchesSubstrings(t *testing.T) {
	cases := []struct {
		question string
		filter   string
		want     bool
	}{
		{"www.example.com.", "example.", true},
		{"myexample.net.", "example.", true},
		{"example.com.", "example.", true},
		// The contract says substring, not canonical suffix: an unqualified
		// fragment must still match, and DNS names stay case-insensitive.
		{"example.com.", "exam", true},
		{"example.com.", "EXAMPLE", true},
		{"unrelated.test.", "example.", false},
		{"anything.test.", "", true},
	}
	for _, tc := range cases {
		if got := dnsLogNameMatches(tc.question, tc.filter); got != tc.want {
			t.Errorf("dnsLogNameMatches(%q, %q) = %v, want %v", tc.question, tc.filter, got, tc.want)
		}
	}
}
