/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestMarshal(t *testing.T) {
	abs, err := filepath.Abs("../example.dae")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	tmpInput := filepath.Join(tmpDir, "example.dae")
	if err = os.WriteFile(tmpInput, raw, 0600); err != nil {
		t.Fatal(err)
	}
	merger := NewMerger(tmpInput)
	sections, _, err := merger.Merge()
	if err != nil {
		t.Fatal(err)
	}
	conf1, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	b, err := conf1.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(b))
	// Read it again.
	tmpOutput := filepath.Join(tmpDir, "test.dae")
	if err = os.WriteFile(tmpOutput, b, 0600); err != nil {
		t.Fatal(err)
	}
	sections, _, err = NewMerger(tmpOutput).Merge()
	if err != nil {
		t.Fatal(err)
	}
	conf2, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := conf2.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(b, b2) {
		t.Fatalf("marshal should be idempotent after one round-trip\nfirst:\n%s\nsecond:\n%s", string(b), string(b2))
	}
	if !bytes.Contains(b, []byte(`filter:name("US_node") [add_latency:"-500ms"]`)) {
		t.Fatalf("first marshal dropped or mis-attached US_node annotation\n%s", string(b))
	}
	if bytes.Contains(b, []byte(`filter:name("HK_node") [add_latency:`)) {
		t.Fatalf("first marshal attached add_latency to HK_node\n%s", string(b))
	}
}

func TestMarshalPreservesGroupFilterWithMoreThanFiveParams(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
group {
    g {
        filter: name(n1, n2, n3, n4, n5, n6)
        filter: name(n1, n2, n3, n4, n5, n6) [add_latency: -500ms]
        policy: min_avg10
    }
}
routing {
    fallback: g
}
`)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Group) != 1 || len(conf.Group[0].Filter) != 2 {
		t.Fatalf("unexpected parsed group filters: %#v", conf.Group)
	}
	if got := len(conf.Group[0].Filter[0][0].Params); got != 6 {
		t.Fatalf("parsed filter params = %d, want 6", got)
	}
	b, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("...")) {
		t.Fatalf("marshal truncated function params:\n%s", string(b))
	}
	if !bytes.Contains(b, []byte("n6")) {
		t.Fatalf("marshal dropped n6:\n%s", string(b))
	}
	if !bytes.Contains(b, []byte("[add_latency:")) {
		t.Fatalf("marshal dropped filter annotation:\n%s", string(b))
	}

	sections2, err := config_parser.Parse(string(b))
	if err != nil {
		t.Fatalf("parse-after-marshal: %v\n%s", err, string(b))
	}
	conf2, err := New(sections2)
	if err != nil {
		t.Fatalf("decode-after-marshal: %v\n%s", err, string(b))
	}
	if len(conf2.Group) != 1 || len(conf2.Group[0].Filter) != 2 {
		t.Fatalf("round-trip group filters: %#v", conf2.Group)
	}
	for i, f := range conf2.Group[0].Filter {
		if len(f) != 1 {
			t.Fatalf("filter[%d] and-functions = %d, want 1", i, len(f))
		}
		if got := len(f[0].Params); got != 6 {
			t.Fatalf("filter[%d] params = %d, want 6 from:\n%s", i, got, string(b))
		}
		if got := f[0].Params[5].Val; got != "n6" {
			t.Fatalf("filter[%d] last param = %q, want n6", i, got)
		}
	}
	if len(conf2.Group[0].FilterAnnotation) != 2 || len(conf2.Group[0].FilterAnnotation[1]) != 1 {
		t.Fatalf("round-trip annotations: %#v", conf2.Group[0].FilterAnnotation)
	}
	if len(conf2.Group[0].FilterAnnotation[0]) != 0 {
		t.Fatalf("first filter picked up annotation: %#v", conf2.Group[0].FilterAnnotation[0])
	}
	if got := conf2.Group[0].FilterAnnotation[1][0]; got.Key != "add_latency" || got.Val != "-500ms" {
		t.Fatalf("round-trip annotation = %#v", conf2.Group[0].FilterAnnotation[1])
	}
}

func TestMarshalPreservesGroupFilterAnnotation(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
group {
    g {
        filter: name(HK_node)
        filter: name(US_node) [add_latency: -500ms]
        policy: min_avg10
    }
}
routing {
    fallback: g
}
`)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Group) != 1 || len(conf.Group[0].Filter) != 2 || len(conf.Group[0].FilterAnnotation) != 2 {
		t.Fatalf("unexpected parsed group: filters=%d annotations=%d", len(conf.Group[0].Filter), len(conf.Group[0].FilterAnnotation))
	}
	b, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`filter:name("US_node") [add_latency:"-500ms"]`)) {
		t.Fatalf("marshal dropped or mis-attached US_node annotation:\n%s", string(b))
	}
	if bytes.Contains(b, []byte(`filter:name("HK_node") [add_latency:`)) {
		t.Fatalf("marshal attached add_latency to HK_node:\n%s", string(b))
	}

	sections2, err := config_parser.Parse(string(b))
	if err != nil {
		t.Fatalf("parse-after-marshal: %v\n%s", err, string(b))
	}
	conf2, err := New(sections2)
	if err != nil {
		t.Fatalf("decode-after-marshal: %v\n%s", err, string(b))
	}
	if len(conf2.Group) != 1 || len(conf2.Group[0].FilterAnnotation) != 2 {
		t.Fatalf("round-trip annotations: %#v", conf2.Group)
	}
	if len(conf2.Group[0].FilterAnnotation[0]) != 0 {
		t.Fatalf("HK_node picked up annotation: %#v", conf2.Group[0].FilterAnnotation[0])
	}
	if got := conf2.Group[0].FilterAnnotation[1]; len(got) != 1 || got[0].Key != "add_latency" || got[0].Val != "-500ms" {
		t.Fatalf("US_node annotation = %#v", conf2.Group[0].FilterAnnotation[1])
	}
}

func TestMarshalPreservesRoutingOutboundParams(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing {
    ip(1.1.1.1) -> g(n1, n2, n3, n4, n5, n6)
    fallback: direct
}
`)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Routing.Rules) != 1 {
		t.Fatalf("parsed rules = %d, want 1", len(conf.Routing.Rules))
	}
	if got := len(conf.Routing.Rules[0].Outbound.Params); got != 6 {
		t.Fatalf("parsed outbound params = %d, want 6", got)
	}
	b, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("...")) {
		t.Fatalf("marshal truncated routing outbound:\n%s", string(b))
	}
	if !bytes.Contains(b, []byte("n6")) {
		t.Fatalf("marshal dropped outbound n6:\n%s", string(b))
	}
}

// TestMarshalPolicyFixedListIsSupported is a regression guard: a group whose
// policy is written as a function call (`policy: fixed(0)`) stores an
// any-typed []*config_parser.Function, which marshalLeaf's interface switch had
// no case for and rejected as an "unknown leaf type".
func TestMarshalPolicyFixedListIsSupported(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
group {
    g {
        policy: fixed(0)
        filter: name(keyword: hk)
    }
}
routing {
    fallback: g
}
`)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Group) != 1 {
		t.Fatalf("groups = %d, want 1", len(conf.Group))
	}
	b, err := conf.Marshal(2)
	if err != nil {
		t.Fatalf("Marshal with policy: fixed(N) failed: %v", err)
	}
	if !bytes.Contains(b, []byte("policy:fixed(")) {
		t.Fatalf("marshalled policy line missing:\n%s", string(b))
	}
	// The marshalled config must decode again with the same policy value.
	sections2, err := config_parser.Parse(string(b))
	if err != nil {
		t.Fatalf("parse-after-marshal: %v\n%s", err, string(b))
	}
	conf2, err := New(sections2)
	if err != nil {
		t.Fatalf("decode-after-marshal: %v\n%s", err, string(b))
	}
	if len(conf2.Group) != 1 {
		t.Fatalf("round-trip groups = %d, want 1", len(conf2.Group))
	}
	policy, err := ParseFunctionListOrString(conf2.Group[0].Policy)
	if err != nil {
		t.Fatalf("round-trip policy: %v", err)
	}
	if len(policy) != 1 || policy[0].Name != "fixed" || len(policy[0].Params) != 1 || policy[0].Params[0].Val != "0" {
		t.Fatalf("round-trip policy = %#v, want fixed(0)", policy)
	}
}

// TestMarshalLeafInterfaceFunctionShapes covers the two shapes marshalLeaf must
// render for interface-typed fields, and pins that an unknown shape still fails
// loudly instead of being dropped.
func TestMarshalLeafInterfaceFunctionShapes(t *testing.T) {
	var list any = []*config_parser.Function{{
		Name:   "fixed",
		Params: []*config_parser.Param{{Val: "0"}},
	}}
	m := Marshaller{IndentSpace: 2}
	if err := m.marshalLeaf("policy", reflect.ValueOf(list), 0, reflect.Value{}); err != nil {
		t.Fatalf("[]*Function leaf: %v", err)
	}
	if got := m.buf.String(); !strings.Contains(got, `policy:fixed("0")`) {
		t.Fatalf("[]*Function leaf rendered %q", got)
	}

	var andList any = [][]*config_parser.Function{{
		{Name: "domain", Params: []*config_parser.Param{{Val: "a.com"}}},
	}}
	m2 := Marshaller{IndentSpace: 2}
	if err := m2.marshalLeaf("filter", reflect.ValueOf(andList), 0, reflect.Value{}); err != nil {
		t.Fatalf("[][]*Function leaf: %v", err)
	}
	if got := m2.buf.String(); !strings.Contains(got, `filter:domain("a.com")`) {
		t.Fatalf("[][]*Function leaf rendered %q", got)
	}

	var unsupported any = struct{ A int }{}
	m3 := Marshaller{IndentSpace: 2}
	if err := m3.marshalLeaf("x", reflect.ValueOf(unsupported), 0, reflect.Value{}); err == nil {
		t.Fatal("unsupported leaf shape must fail loudly, not be dropped")
	}
}
