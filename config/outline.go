/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, v2rayA Organization <team@v2raya.org>
 */

package config

import (
	jsoniter "github.com/json-iterator/go"
	"reflect"
	"sort"
)

type Outline struct {
	Leaves    []string       `json:"leaves"`
	Structure []*OutlineElem `json:"structure"`
}

type OutlineElem struct {
	Name      string         `json:"name,omitempty"`
	Mapping   string         `json:"mapping,omitempty"`
	Kind      string         `json:"kind,omitempty"`
	Type      string         `json:"type,omitempty"`
	ElemType  string         `json:"elemType,omitempty"`
	Desc      string         `json:"desc,omitempty"`
	Structure []*OutlineElem `json:"structure,omitempty"`
}

func ExportOutline() *Outline {
	exporter := outlineExporter{
		leaves: make(map[string]struct{}),
	}
	// Get structure.
	t := reflect.TypeOf(Params{})
	structure := exporter.exportStruct(t, SectionSummaryDesc)
	// Get leaves.
	var leaves []string
	for k := range exporter.leaves {
		leaves = append(leaves, k)
	}
	sort.Strings(leaves)

	return &Outline{
		Leaves:    leaves,
		Structure: structure,
	}
}

func ExportOutlineJson() string {
	b, err := jsoniter.MarshalIndent(ExportOutline(), "", "  ")
	if err != nil {
		panic(err)
	}
	return string(b)
}

type outlineExporter struct {
	leaves map[string]struct{}
}

func (e *outlineExporter) exportStruct(t reflect.Type, descSource Desc) (outlines []*OutlineElem) {
	for i := 0; i < t.NumField(); i++ {
		section := t.Field(i)
		// Parse desc.
		var desc string
		if descSource != nil {
			desc = descSource[section.Tag.Get("mapstructure")]
		}
		// Parse children.
		var children []*OutlineElem
		switch section.Type.Kind() {
		case reflect.Struct:
			nextDescSource := SectionDescription[section.Tag.Get("desc")]
			children = e.exportStruct(section.Type, nextDescSource)
		}
		// Parse elem type.
		var kind string
		var typ reflect.Type
		switch section.Type.Kind() {
		case reflect.Array, reflect.Slice:
			typ = section.Type.Elem()
			kind = "array"
		default:
			typ = section.Type
		}
		if typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if len(children) == 0 {
			// Record leaves.
			e.leaves[typ.String()] = struct{}{}
		}
		outlines = append(outlines, &OutlineElem{
			Name:      section.Name,
			Mapping:   section.Tag.Get("mapstructure"),
			Kind:      kind,
			Type:      typ.String(),
			Desc:      desc,
			Structure: children,
		})
	}
	return outlines
}
