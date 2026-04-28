/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"reflect"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

type configSectionDecoder func(conf *Config, section *config_parser.Section) error

type configSectionSpec struct {
	name     string
	required bool
	decode   configSectionDecoder
}

var configSectionSpecs = []configSectionSpec{
	{name: "global", required: true, decode: decodeGlobalSection},
	{name: "subscription", decode: decodeSubscriptionSection},
	{name: "node", decode: decodeNodeSection},
	{name: "group", decode: decodeGroupSection},
	{name: "routing", required: true, decode: decodeRoutingSection},
	{name: "dns", decode: decodeDnsSection},
}

func lookupConfigSectionSpec(sectionName string) *configSectionSpec {
	for i := range configSectionSpecs {
		if configSectionSpecs[i].name == sectionName {
			return &configSectionSpecs[i]
		}
	}
	return nil
}

func decodeConfigSection(conf *Config, sectionName string, section *config_parser.Section) error {
	if conf == nil {
		return fmt.Errorf("nil config")
	}
	spec := lookupConfigSectionSpec(sectionName)
	if spec == nil {
		return fmt.Errorf("unknown section: %v", sectionName)
	}
	if section == nil {
		return fmt.Errorf("nil section: %v", sectionName)
	}
	return spec.decode(conf, section)
}

func decodeGlobalSection(conf *Config, section *config_parser.Section) error {
	if err := SectionParser(reflect.ValueOf(&conf.Global), section); err != nil {
		return err
	}
	conf.Global.SoMarkFromDaeSet = sectionHasParam(section, "so_mark_from_dae")
	return nil
}

func decodeSubscriptionSection(conf *Config, section *config_parser.Section) error {
	return SectionParser(reflect.ValueOf(&conf.Subscription), section)
}

func decodeNodeSection(conf *Config, section *config_parser.Section) error {
	return SectionParser(reflect.ValueOf(&conf.Node), section)
}

func decodeGroupSection(conf *Config, section *config_parser.Section) error {
	return SectionParser(reflect.ValueOf(&conf.Group), section)
}

func decodeRoutingSection(conf *Config, section *config_parser.Section) error {
	return SectionParser(reflect.ValueOf(&conf.Routing), section)
}

func decodeDnsSection(conf *Config, section *config_parser.Section) error {
	return SectionParser(reflect.ValueOf(&conf.Dns), section)
}
