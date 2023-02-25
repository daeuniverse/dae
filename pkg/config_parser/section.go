/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
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
		Type:  ItemType_Param,
		Value: section,
	}
}

type Item struct {
	Type  ItemType
	Value interface{}
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
}

func (p *Param) String(compact bool, quoteVal bool) string {
	var quote func(string) string
	if quoteVal {
		quote = strconv.Quote
	} else {
		quote = func(s string) string { return s }
	}
	if p.Key == "" {
		return quote(p.Val)
	}
	if p.AndFunctions != nil {
		a := paramAndFunctions{
			Key:          p.Key,
			AndFunctions: p.AndFunctions,
		}
		return a.String(compact, quoteVal)
	}
	if compact {
		return p.Key + ":" + quote(p.Val)
	} else {
		return p.Key + ": " + quote(p.Val)
	}
}

type Function struct {
	Name   string
	Not    bool
	Params []*Param
}

func (f *Function) String(compact bool, quoteVal bool, omitEmpty bool) string {
	var builder strings.Builder
	if f.Not {
		builder.WriteString("!")
	}
	builder.WriteString(f.Name)
	if !(omitEmpty && len(f.Params) == 0) {
		builder.WriteString("(")
		var strParamList []string
		for _, p := range f.Params {
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
		strFunctionList = append(strFunctionList, f.String(compact, quoteVal, false))
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
		n += len(f.Params)
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
		builder.WriteString(fmt.Sprintf("%v%v(%v)", symNot, f.Name, paramBuilder.String()))
	}
	if compact {
		builder.WriteString("->" + r.Outbound.String(compact, quoteVal, true))
	} else {
		builder.WriteString(" -> " + r.Outbound.String(compact, quoteVal, true))
	}
	return builder.String()
}
