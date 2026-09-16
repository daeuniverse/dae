//go:build dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	_ "embed"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

//go:embed kern/tproxy.c
var tproxySource string

var bpfMapDeclarationPattern = regexp.MustCompile("(?m)^}\\s*([a-z_][a-z0-9_]*)\\s+SEC\\(\"\\.maps\"\\);$")

func TestBpfStubMapParityWithKernelSource(t *testing.T) {
	t.Parallel()

	want := bpfMapNamesFromKernelSource(t)
	assertBpfStubMapNames(t, "bpfMapSpecs", reflect.TypeFor[bpfMapSpecs](), want)
	assertBpfStubMapNames(t, "bpfMaps", reflect.TypeFor[bpfMaps](), want)
}

func bpfMapNamesFromKernelSource(t *testing.T) []string {
	t.Helper()

	matches := bpfMapDeclarationPattern.FindAllStringSubmatch(tproxySource, -1)
	if len(matches) == 0 {
		t.Fatal("did not find BPF map declarations in kern/tproxy.c")
	}
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		names = append(names, match[1])
	}
	sort.Strings(names)
	return names
}

func assertBpfStubMapNames(t *testing.T, typeName string, typ reflect.Type, want []string) {
	t.Helper()

	got := make([]string, 0, typ.NumField())
	for field := range typ.Fields() {
		if name := field.Tag.Get("ebpf"); name != "" {
			got = append(got, name)
		}
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s map tags differ from kern/tproxy.c\nwant: %v\n got: %v", typeName, want, got)
	}
}
