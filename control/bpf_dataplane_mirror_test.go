//go:build !dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"reflect"
	"testing"
)

func TestDataplaneProgramsAndMapsComplete(t *testing.T) {
	assertDataplaneMirrorComplete(
		t,
		"program",
		reflect.TypeFor[bpfPrograms](),
		reflect.TypeFor[bpfDataplanePrograms](),
		tcpRelayOffloadPrograms,
	)
	assertDataplaneMirrorComplete(
		t,
		"map",
		reflect.TypeFor[bpfMaps](),
		reflect.TypeFor[bpfDataplaneMaps](),
		tcpRelayOffloadMaps,
	)
}

func TestAssignDataplaneToBpfCopiesMandatoryObjects(t *testing.T) {
	dataplane := new(bpfDataplane)
	populatePointerFields(reflect.ValueOf(&dataplane.bpfDataplanePrograms).Elem())
	populatePointerFields(reflect.ValueOf(&dataplane.bpfDataplaneMaps).Elem())

	objects := new(bpfObjects)
	assignDataplaneToBpf(objects, dataplane)
	assertPointerFieldsEqual(t, "program", reflect.ValueOf(&dataplane.bpfDataplanePrograms).Elem(), reflect.ValueOf(&objects.bpfPrograms).Elem())
	assertPointerFieldsEqual(t, "map", reflect.ValueOf(&dataplane.bpfDataplaneMaps).Elem(), reflect.ValueOf(&objects.bpfMaps).Elem())
}

func populatePointerFields(value reflect.Value) {
	for _, field := range value.Fields() {
		field.Set(reflect.New(field.Type().Elem()))
	}
}

func assertPointerFieldsEqual(t *testing.T, objectKind string, source, destination reflect.Value) {
	t.Helper()
	for i := 0; i < source.NumField(); i++ {
		field := source.Type().Field(i)
		got := destination.FieldByName(field.Name)
		if !got.IsValid() {
			t.Errorf("canonical BPF objects missing %s field %q", objectKind, field.Name)
			continue
		}
		if got.Pointer() != source.Field(i).Pointer() {
			t.Errorf("canonical BPF objects did not receive %s %q", objectKind, field.Tag.Get("ebpf"))
		}
	}
}

func assertDataplaneMirrorComplete(t *testing.T, objectKind string, generated, mandatory reflect.Type, optIn []string) {
	t.Helper()
	want := ebpfTaggedFields(generated)
	for _, name := range optIn {
		delete(want, name)
	}
	got := ebpfTaggedFields(mandatory)
	for name := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("mandatory dataplane missing %s %q", objectKind, name)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("mandatory dataplane has unexpected %s %q", objectKind, name)
		}
	}
}

func ebpfTaggedFields(typ reflect.Type) map[string]struct{} {
	fields := make(map[string]struct{}, typ.NumField())
	for field := range typ.Fields() {
		if name := field.Tag.Get("ebpf"); name != "" {
			fields[name] = struct{}{}
		}
	}
	return fields
}
