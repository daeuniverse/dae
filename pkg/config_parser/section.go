/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import (
	"fmt"
	"strconv"
	"strings"
)

type ItemType int

const (
	ItemType_RoutingRule ItemType = iota
	ItemType_Param
	ItemType_Section
)

func (t ItemType) String() string {
	switch t {
	case ItemType_RoutingRule:
		return "RoutingRule"
	case ItemType_Param:
		return "Param"
	case ItemType_Section:
		return "Section"
	default:
		return "<Unknown>"
	}
}

func NewRoutingRuleItem(rule *RoutingRule) *Item {
	return &Item{
		Type:  ItemType_RoutingRule,
		Value: rule,
	}
}

func NewParamItem(param *Param) *Item {
	return &Item{
		Type:  ItemType_Param,
		Value: param,
	}
}

func NewSectionItem(section *Section) *Item {
	return &Item{
		Type:  ItemType_Section,
		Value: section,
	}
}

type Item struct {
	Type  ItemType
	Value any
}

func (i *Item) String(compact bool, quoteVal bool) string {
	var builder strings.Builder
	builder.WriteString("type: " + i.Type.String() + "\n")
	var content string
	switch val := i.Value.(type) {
	case *RoutingRule:
		content = val.String(false, compact, quoteVal)
	case *Param:
		content = val.String(false, quoteVal)
	case *Section:
		content = val.String(compact, quoteVal)
	default:
		return "<Unknown>\n"
	}
	lines := strings.Split(content, "\n")
	for i := range lines {
		lines[i] = "\t" + lines[i]
	}
	builder.WriteString(strings.Join(lines, "\n"))
	return builder.String()
}

type Section struct {
	Name  string
	Items []*Item
}

func (s *Section) String(compact bool, quoteVal bool) string {
	var builder strings.Builder
	builder.WriteString("section: " + s.Name + "\n")
	var strItemList []string
	for _, item := range s.Items {
		lines := strings.Split(item.String(compact, quoteVal), "\n")
		for i := range lines {
			lines[i] = "\t" + lines[i]
		}
		strItemList = append(strItemList, strings.Join(lines, "\n"))
	}
	builder.WriteString(strings.Join(strItemList, "\n"))
	return builder.String()
}

type Param struct {
	// Key may be empty.
	Key string

	// Either Val or AndFunctions is empty.
	Val          string
	AndFunctions []*Function

	// Annotation is optional
	Annotation []*Param
}

func (p *Param) String(compact bool, quoteVal bool) string {
	var quote func(string) string
	if quoteVal {
		quote = strconv.Quote
	} else {
		quote = func(s string) string { return s }
	}
	var s string
	switch {
	case p.Key == "":
		s = quote(p.Val)
	case p.AndFunctions != nil:
		a := paramAndFunctions{
			Key:          p.Key,
			AndFunctions: p.AndFunctions,
		}
		s = a.String(compact, quoteVal)
	case compact:
		s = p.Key + ":" + quote(p.Val)
	default:
		s = p.Key + ": " + quote(p.Val)
	}
	return s + formatAnnotation(p.Annotation, compact, quoteVal)
}

func formatAnnotation(ann []*Param, compact bool, quoteVal bool) string {
	if len(ann) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ann))
	for _, a := range ann {
		parts = append(parts, a.String(compact, quoteVal))
	}
	sep := ", "
	if compact {
		sep = ","
	}
	return " [" + strings.Join(parts, sep) + "]"
}

type Function struct {
	Name   string
	Not    bool
	Params []*Param
}

func (f *Function) String(compact bool, quoteVal bool, omitEmpty bool) string {
	return f.format(compact, quoteVal, omitEmpty, false)
}

// MarshalString is the lossless form of String: every param is emitted.
// String remains truncated at 5 params for log/debug display.
func (f *Function) MarshalString(compact bool, quoteVal bool, omitEmpty bool) string {
	return f.format(compact, quoteVal, omitEmpty, true)
}

func (f *Function) format(compact bool, quoteVal bool, omitEmpty bool, unlimited bool) string {
	var builder strings.Builder
	if f.Not {
		builder.WriteString("!")
	}
	builder.WriteString(f.Name)
	if !omitEmpty || len(f.Params) != 0 {
		builder.WriteString("(")
		var strParamList []string
		for i, p := range f.Params {
			if !unlimited && i >= 5 {
				strParamList = append(strParamList, "...")
				break
			}
			strParamList = append(strParamList, p.String(compact, quoteVal))
		}
		if compact {
			builder.WriteString(strings.Join(strParamList, ","))
		} else {
			builder.WriteString(strings.Join(strParamList, ", "))
		}
		builder.WriteString(")")
	}
	return builder.String()
}

type paramAndFunctions struct {
	Key          string
	AndFunctions []*Function
}

func (p *paramAndFunctions) String(compact bool, quoteVal bool) string {
	var builder strings.Builder
	if compact {
		builder.WriteString(p.Key + ":")
	} else {
		builder.WriteString(p.Key + ": ")
	}
	var strFunctionList []string
	for _, f := range p.AndFunctions {
		strFunctionList = append(strFunctionList, f.MarshalString(compact, quoteVal, false))
	}
	if compact {
		builder.WriteString(strings.Join(strFunctionList, "&&"))
	} else {
		builder.WriteString(strings.Join(strFunctionList, " && "))
	}
	return builder.String()
}

type RoutingRule struct {
	AndFunctions []*Function
	Outbound     Function
}

// DisplayParamLimit caps how many parameters one function renders in
// DisplayString.
//
// A single geosite-expanded rule carries thousands of suffixes (this deployment
// renders one as 8.5 MB of JSON), which is unusable in a UI and large enough to
// make the rules endpoint the slowest one the dashboard polls. String and
// MarshalString stay lossless: identify and hash rules with those, never with
// DisplayString.
const DisplayParamLimit = 8

// DisplayString renders a rule for API and UI display, collapsing oversized
// parameter lists to DisplayParamLimit entries plus a "+N more" marker.
func (r *RoutingRule) DisplayString(compact bool, quoteVal bool) string {
	if r == nil {
		return ""
	}
	var builder strings.Builder
	for i, f := range r.AndFunctions {
		if i != 0 {
			if compact {
				builder.WriteString("&&")
			} else {
				builder.WriteString(" && ")
			}
		}
		builder.WriteString(displayFunction(f, compact, quoteVal))
	}
	if compact {
		builder.WriteString("->" + r.Outbound.MarshalString(compact, quoteVal, true))
	} else {
		builder.WriteString(" -> " + r.Outbound.MarshalString(compact, quoteVal, true))
	}
	return builder.String()
}

func displayFunction(f *Function, compact bool, quoteVal bool) string {
	if f == nil {
		return ""
	}
	var paramBuilder strings.Builder
	if len(f.Params) > DisplayParamLimit {
		rendered := make([]string, 0, DisplayParamLimit+1)
		for _, param := range f.Params[:DisplayParamLimit] {
			rendered = append(rendered, param.String(compact, quoteVal))
		}
		rendered = append(rendered, fmt.Sprintf("+%d more", len(f.Params)-DisplayParamLimit))
		if compact {
			paramBuilder.WriteString(strings.Join(rendered, ","))
		} else {
			paramBuilder.WriteString(strings.Join(rendered, ", "))
		}
	} else {
		for j, param := range f.Params {
			if j != 0 {
				if compact {
					paramBuilder.WriteString(",")
				} else {
					paramBuilder.WriteString(", ")
				}
			}
			paramBuilder.WriteString(param.String(compact, quoteVal))
		}
	}
	symNot := ""
	if f.Not {
		symNot = "!"
	}
	return fmt.Sprintf("%v%v(%v)", symNot, f.Name, paramBuilder.String())
}

func (r *RoutingRule) String(replaceParamWithN bool, compact bool, quoteVal bool) string {
	var builder strings.Builder
	var n int
	for i, f := range r.AndFunctions {
		if i != 0 {
			if compact {
				builder.WriteString("&&")
			} else {
				builder.WriteString(" && ")
			}
		}
		var paramBuilder strings.Builder
		n = len(f.Params)
		if replaceParamWithN {
			paramBuilder.WriteString("[n = " + strconv.Itoa(n) + "]")
		} else {
			for j, param := range f.Params {
				if j != 0 {
					if compact {
						paramBuilder.WriteString(",")
					} else {
						paramBuilder.WriteString(", ")
					}
				}
				paramBuilder.WriteString(param.String(compact, quoteVal))
			}
		}
		symNot := ""
		if f.Not {
			symNot = "!"
		}
		fmt.Fprintf(&builder, "%v%v(%v)", symNot, f.Name, paramBuilder.String())
	}
	if compact {
		builder.WriteString("->" + r.Outbound.MarshalString(compact, quoteVal, true))
	} else {
		builder.WriteString(" -> " + r.Outbound.MarshalString(compact, quoteVal, true))
	}
	return builder.String()
}
