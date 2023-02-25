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
	IsArray   bool           `json:"isArray,omitempty"`
	Type      string         `json:"type,omitempty"`
	ElemType  string         `json:"elemType,omitempty"`
	Desc      string         `json:"desc,omitempty"`
	Structure []*OutlineElem `json:"structure,omitempty"`
}

func ExportOutline() *Outline {
	// Get structure.
	t := reflect.TypeOf(Params{})
	exporter := outlineExporter{
		leaves:       make(map[string]struct{}),
		pktPathScope: t.PkgPath(),
	}
	structure := exporter.exportStruct(t, SectionSummaryDesc, false)
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
	leaves       map[string]struct{}
	pktPathScope string
}

func (e *outlineExporter) exportStruct(t reflect.Type, descSource Desc, inheritSource bool) (outlines []*OutlineElem) {
	for i := 0; i < t.NumField(); i++ {
		section := t.Field(i)
		// Parse desc.
		var desc string
		if descSource != nil {
			desc = descSource[section.Tag.Get("mapstructure")]
		}
		// Parse elem type.
		var isArray bool
		var typ reflect.Type
		switch section.Type.Kind() {
		case reflect.Slice, reflect.Array:
			typ = section.Type.Elem()
			isArray = true
		default:
			typ = section.Type
		}
		if typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		// Parse children.
		var children []*OutlineElem
		switch typ.Kind() {
		case reflect.Struct:
			var nextDescSource Desc
			if inheritSource {
				nextDescSource = descSource
			} else {
				nextDescSource = SectionDescription[section.Tag.Get("desc")]
			}
			if typ.PkgPath() == "" || typ.PkgPath() == e.pktPathScope {
				children = e.exportStruct(typ, nextDescSource, true)
			}
		}
		if len(children) == 0 {
			// Record leaves.
			e.leaves[typ.String()] = struct{}{}
		}
		outlines = append(outlines, &OutlineElem{
			Name:      section.Name,
			Mapping:   section.Tag.Get("mapstructure"),
			IsArray:   isArray,
			Type:      typ.String(),
			Desc:      desc,
			Structure: children,
		})
	}
	return outlines
}
