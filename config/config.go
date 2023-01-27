/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package config

import (
	"fmt"
	"github.com/v2rayA/dae/pkg/config_parser"
	"reflect"
	"time"
)

type Global struct {
	TproxyPort       uint16        `mapstructure:"tproxy_port" default:"12345"`
	CheckUrl         string        `mapstructure:"check_url" default:"https://connectivitycheck.gstatic.com/generate_204"`
	CheckInterval    time.Duration `mapstructure:"check_interval" default:"15s"`
	DnsUpstream      string        `mapstructure:"dns_upstream" default:"208.67.222.222:5353"`
	IngressInterface string        `mapstructure:"ingress_interface" required:""`
}

type Group struct {
	Name  string
	Param GroupParam
}

type GroupParam struct {
	Filter []*config_parser.Function `mapstructure:"filter" required:""`
	Policy interface{}               `mapstructure:"policy" required:""`
}

type Routing struct {
	Rules []*config_parser.RoutingRule `mapstructure:"_"`
	Final string                       `mapstructure:"final" required:""`
}

type Params struct {
	Global       Global   `mapstructure:"global" parser:"ParamParser"`
	Subscription []string `mapstructure:"subscription" parser:"StringListParser"`
	Node         []string `mapstructure:"node" parser:"StringListParser"`
	Group        []Group  `mapstructure:"group" parser:"GroupListParser"`
	Routing      Routing  `mapstructure:"routing" parser:"RoutingRuleAndParamParser"`
}

// New params from sections. This func assumes merging (section "include") and deduplication for sections has been executed.
func New(sections []*config_parser.Section) (params *Params, err error) {
	// Set up name to section for further use.
	type Section struct {
		Val    *config_parser.Section
		Parsed bool
	}
	nameToSection := make(map[string]*Section)
	for _, section := range sections {
		nameToSection[section.Name] = &Section{Val: section}
	}

	params = &Params{}
	// Use specified parser to parse corresponding section.
	_val := reflect.ValueOf(params)
	val := _val.Elem()
	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		structField := typ.Field(i)

		// Find corresponding section from sections.
		sectionName, ok := structField.Tag.Lookup("mapstructure")
		if !ok {
			return nil, fmt.Errorf("no mapstructure is specified in field %v", structField.Name)
		}
		section, ok := nameToSection[sectionName]
		if !ok {
			return nil, fmt.Errorf("section %v is required but not provided", sectionName)
		}

		// Find corresponding parser func.
		parserName, ok := structField.Tag.Lookup("parser")
		if !ok {
			return nil, fmt.Errorf("no parser is specified in field %v", structField.Name)
		}
		parserFunc, ok := ParserMap[parserName]
		if !ok {
			return nil, fmt.Errorf("unknown parser %v in field %v", parserName, structField.Name)
		}

		// Parse section and unmarshal to field.
		if err := parserFunc(field.Addr(), section.Val); err != nil {
			return nil, fmt.Errorf("failed to parse \"%v\": %w", sectionName, err)
		}
		section.Parsed = true
	}

	// Report unknown. Not "unused" because we assume deduplication has been executed before this func.
	for name, section := range nameToSection {
		if !section.Parsed {
			return nil, fmt.Errorf("unknown section: %v", name)
		}
	}
	return params, nil
}
