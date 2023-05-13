/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"reflect"
	"time"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

type Global struct {
	TproxyPort        uint16 `mapstructure:"tproxy_port" default:"12345"`
	TproxyPortProtect bool   `mapstructure:"tproxy_port_protect" default:"true"`
	SoMarkFromDae     uint32 `mapstructure:"so_mark_from_dae"`
	LogLevel          string `mapstructure:"log_level" default:"info"`
	// We use DirectTcpCheckUrl to check (tcp)*(ipv4/ipv6) connectivity for direct.
	//DirectTcpCheckUrl string `mapstructure:"direct_tcp_check_url" default:"http://www.qualcomm.cn/generate_204"`
	TcpCheckUrl               []string      `mapstructure:"tcp_check_url" default:"http://cp.cloudflare.com,1.1.1.1,2606:4700:4700::1111"`
	UdpCheckDns               []string      `mapstructure:"udp_check_dns" default:"dns.google.com:53,8.8.8.8,2001:4860:4860::8888"`
	CheckInterval             time.Duration `mapstructure:"check_interval" default:"30s"`
	CheckTolerance            time.Duration `mapstructure:"check_tolerance" default:"0"`
	LanInterface              []string      `mapstructure:"lan_interface"`
	WanInterface              []string      `mapstructure:"wan_interface"`
	AllowInsecure             bool          `mapstructure:"allow_insecure" default:"false"`
	DialMode                  string        `mapstructure:"dial_mode" default:"domain"`
	DisableWaitingNetwork     bool          `mapstructure:"disable_waiting_network" default:"false"`
	AutoConfigKernelParameter bool          `mapstructure:"auto_config_kernel_parameter" default:"false"`
	SniffingTimeout           time.Duration `mapstructure:"sniffing_timeout" default:"100ms"`
}

type FunctionOrString interface{}

func FunctionOrStringToFunction(fs FunctionOrString) (f *config_parser.Function) {
	switch fs := fs.(type) {
	case string:
		return &config_parser.Function{Name: fs}
	case *config_parser.Function:
		return fs
	default:
		panic(fmt.Sprintf("unknown type of 'fallback' in section routing: %T", fs))
	}
}

type FunctionListOrString interface{}

func FunctionListOrStringToFunctionList(fs FunctionListOrString) (f []*config_parser.Function) {
	switch fs := fs.(type) {
	case string:
		return []*config_parser.Function{{Name: fs}}
	case []*config_parser.Function:
		return fs
	default:
		panic(fmt.Sprintf("unknown type of 'fallback' in section routing: %T", fs))
	}
}

type Group struct {
	Name string `mapstructure:"_"`

	Filter []*config_parser.Function `mapstructure:"filter"`
	Policy FunctionListOrString      `mapstructure:"policy" required:""`
}

type DnsRequestRouting struct {
	Rules    []*config_parser.RoutingRule `mapstructure:"_"`
	Fallback FunctionOrString             `mapstructure:"fallback" required:""`
}
type DnsResponseRouting struct {
	Rules    []*config_parser.RoutingRule `mapstructure:"_"`
	Fallback FunctionOrString             `mapstructure:"fallback" required:""`
}
type DnsRouting struct {
	Request  DnsRequestRouting  `mapstructure:"request"`
	Response DnsResponseRouting `mapstructure:"response"`
}
type KeyableString string
type Dns struct {
	IpVersionPrefer int             `mapstructure:"ipversion_prefer"`
	Upstream        []KeyableString `mapstructure:"upstream"`
	Routing         DnsRouting      `mapstructure:"routing"`
}

type Routing struct {
	Rules    []*config_parser.RoutingRule `mapstructure:"_"`
	Fallback FunctionOrString             `mapstructure:"fallback" default:"direct"`
}

type Config struct {
	Global       Global          `mapstructure:"global" required:"" desc:"GlobalDesc"`
	Subscription []KeyableString `mapstructure:"subscription"`
	Node         []KeyableString `mapstructure:"node"`
	Group        []Group         `mapstructure:"group" desc:"GroupDesc"`
	Routing      Routing         `mapstructure:"routing" required:""`
	Dns          Dns             `mapstructure:"dns" desc:"DnsDesc"`
}

// New params from sections. This func assumes merging (section "include") and deduplication for section names has been executed.
func New(sections []*config_parser.Section) (conf *Config, err error) {
	// Set up name to section for further use.
	type Section struct {
		Val    *config_parser.Section
		Parsed bool
	}
	nameToSection := make(map[string]*Section)
	for _, section := range sections {
		nameToSection[section.Name] = &Section{Val: section}
	}

	conf = &Config{}
	// Use specified parser to parse corresponding section.
	_val := reflect.ValueOf(conf)
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
			if _, required := structField.Tag.Lookup("required"); required {
				return nil, fmt.Errorf("section %v is required but not provided", sectionName)
			} else {
				continue
			}
		}

		// Parse section and unmarshal to field.
		if err := SectionParser(field.Addr(), section.Val); err != nil {
			return nil, fmt.Errorf("failed to parse \"%v\": %w", sectionName, err)
		}
		section.Parsed = true
	}

	// Report unknown. Not "unused" because we assume section name deduplication has been executed before this func.
	for name, section := range nameToSection {
		if section.Val.Name == "include" {
			continue
		}
		if !section.Parsed {
			return nil, fmt.Errorf("unknown section: %v", name)
		}
	}

	// Apply config patches.
	for _, patch := range patches {
		if err = patch(conf); err != nil {
			return nil, err
		}
	}
	return conf, nil
}
