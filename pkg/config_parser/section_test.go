/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import (
	"strings"
	"testing"
)

func TestNewSectionItemUsesSectionType(t *testing.T) {
	item := NewSectionItem(&Section{Name: "routing"})

	if item.Type != ItemType_Section {
		t.Fatalf("expected item type %v, got %v", ItemType_Section, item.Type)
	}
}

func TestItemStringIncludesSectionType(t *testing.T) {
	item := NewSectionItem(&Section{Name: "routing"})

	got := item.String(false, false)
	if got == "" {
		t.Fatal("expected non-empty string representation")
	}
	if !strings.HasPrefix(got, "type: Section") {
		t.Fatalf("expected string to start with %q, got %q", "type: Section", got)
	}
}

func TestParamStringEmptyAnnotationHasNoSuffix(t *testing.T) {
	p := &Param{
		Key: "filter",
		AndFunctions: []*Function{
			{Name: "name", Params: []*Param{{Val: "HK_node"}}},
		},
	}
	got := p.String(false, false)
	want := "filter: name(HK_node)"
	if got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestParamStringEmitsAnnotation(t *testing.T) {
	p := &Param{
		Key: "filter",
		AndFunctions: []*Function{
			{Name: "name", Params: []*Param{{Val: "US_node"}}},
		},
		Annotation: []*Param{{Key: "add_latency", Val: "-500ms"}},
	}
	got := p.String(false, false)
	want := "filter: name(US_node) [add_latency: -500ms]"
	if got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func sixParamNameFunction() *Function {
	return &Function{
		Name: "name",
		Params: []*Param{
			{Val: "n1"},
			{Val: "n2"},
			{Val: "n3"},
			{Val: "n4"},
			{Val: "n5"},
			{Val: "n6"},
		},
	}
}

func TestFunctionStringEllipsizesAtFiveParams(t *testing.T) {
	got := sixParamNameFunction().String(true, true, false)
	if !strings.Contains(got, "...") {
		t.Fatalf("display String should ellipsize at 5 params: %q", got)
	}
	if strings.Contains(got, "n6") {
		t.Fatalf("display String should not include 6th param: %q", got)
	}
}

func TestFunctionMarshalStringKeepsAllParams(t *testing.T) {
	got := sixParamNameFunction().MarshalString(true, true, false)
	if strings.Contains(got, "...") {
		t.Fatalf("MarshalString must not ellipsize: %q", got)
	}
	if !strings.Contains(got, "n6") {
		t.Fatalf("MarshalString missing n6: %q", got)
	}
}

func TestRoutingRuleStringKeepsOutboundParams(t *testing.T) {
	r := &RoutingRule{
		AndFunctions: []*Function{{Name: "ip", Params: []*Param{{Val: "1.1.1.1"}}}},
		Outbound:     *sixParamNameFunction(),
	}
	got := r.String(false, true, true)
	if strings.Contains(got, "...") {
		t.Fatalf("RoutingRule.String marshal path must not ellipsize outbound: %q", got)
	}
	if !strings.Contains(got, "n6") {
		t.Fatalf("RoutingRule.String missing outbound n6: %q", got)
	}
}

func TestParamStringKeepsAllFunctionParams(t *testing.T) {
	p := &Param{
		Key:          "filter",
		AndFunctions: []*Function{sixParamNameFunction()},
		Annotation:   []*Param{{Key: "add_latency", Val: "-500ms"}},
	}
	got := p.String(true, true)
	if strings.Contains(got, "...") {
		t.Fatalf("Param.String used by marshal must not ellipsize: %q", got)
	}
	if !strings.Contains(got, "n6") {
		t.Fatalf("Param.String missing n6: %q", got)
	}
	if !strings.Contains(got, "[add_latency:") {
		t.Fatalf("Param.String dropped annotation: %q", got)
	}
}

func TestParamStringParseRoundTripAnnotation(t *testing.T) {
	sections, err := Parse(`
group {
    g {
        filter: name(US_node) [add_latency: -500ms]
        policy: min
    }
}
`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	param := findParamByKey(t, sections, "filter")
	if len(param.Annotation) != 1 || param.Annotation[0].Key != "add_latency" || param.Annotation[0].Val != "-500ms" {
		t.Fatalf("parser annotation = %#v", param.Annotation)
	}
	got := param.String(false, false)
	if !strings.Contains(got, "[add_latency:") || !strings.Contains(got, "-500ms") {
		t.Fatalf("String dropped annotation: %q", got)
	}

	round := "group { g { " + got + "\npolicy: min } }"
	sections2, err := Parse(round)
	if err != nil {
		t.Fatalf("re-parse %q: %v", got, err)
	}
	param2 := findParamByKey(t, sections2, "filter")
	if len(param2.Annotation) != 1 || param2.Annotation[0].Key != "add_latency" || param2.Annotation[0].Val != "-500ms" {
		t.Fatalf("round-trip annotation = %#v from %q", param2.Annotation, got)
	}
}

func findParamByKey(t *testing.T, sections []*Section, key string) *Param {
	t.Helper()
	var walk func([]*Item) *Param
	walk = func(items []*Item) *Param {
		for _, item := range items {
			switch v := item.Value.(type) {
			case *Param:
				if v.Key == key {
					return v
				}
			case *Section:
				if p := walk(v.Items); p != nil {
					return p
				}
			}
		}
		return nil
	}
	for _, s := range sections {
		if p := walk(s.Items); p != nil {
			return p
		}
	}
	t.Fatalf("param %q not found", key)
	return nil
}
