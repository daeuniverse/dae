/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"time"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

var (
	Version string
)

type Global struct {
	TproxyPort        uint16 `mapstructure:"tproxy_port" default:"12345"`
	TproxyPortProtect bool   `mapstructure:"tproxy_port_protect" default:"true"`
	SoMarkFromDae     uint32 `mapstructure:"so_mark_from_dae"`
	SoMarkFromDaeSet  bool   `mapstructure:"so_mark_from_dae_set"`
	LogLevel          string `mapstructure:"log_level" default:"info"`
	// We use DirectTcpCheckUrl to check (tcp)*(ipv4/ipv6) connectivity for direct.
	// DirectTcpCheckUrl string `mapstructure:"direct_tcp_check_url" default:"http://www.qualcomm.cn/generate_204"`
	TcpCheckUrl           []string      `mapstructure:"tcp_check_url" default:"http://cp.cloudflare.com,1.1.1.1,2606:4700:4700::1111"`
	TcpCheckHttpMethod    string        `mapstructure:"tcp_check_http_method" default:"HEAD"` // Use 'HEAD' because some server implementations bypass accounting for this kind of traffic.
	UdpCheckDns           []string      `mapstructure:"udp_check_dns" default:"dns.google:53,8.8.8.8,2001:4860:4860::8888"`
	CheckInterval         time.Duration `mapstructure:"check_interval" default:"30s"`
	CheckTolerance        time.Duration `mapstructure:"check_tolerance" default:"0"`
	LanInterface          []string      `mapstructure:"lan_interface"`
	WanInterface          []string      `mapstructure:"wan_interface"`
	AllowInsecure         bool          `mapstructure:"allow_insecure" default:"false"`
	DialMode              string        `mapstructure:"dial_mode" default:"domain"`
	DisableWaitingNetwork bool          `mapstructure:"disable_waiting_network" default:"false"`
	DisableTHP            bool          `mapstructure:"disable_thp" default:"true"`
	// Deprecated: not used as of https://github.com/daeuniverse/dae/pull/912.
	EnableLocalTcpFastRedirect bool `mapstructure:"enable_local_tcp_fast_redirect" default:"false"`
	AutoConfigKernelParameter  bool `mapstructure:"auto_config_kernel_parameter" default:"false"`
	// Deprecated: not used as of https://github.com/daeuniverse/dae/pull/458.
	AutoConfigFirewallRule bool          `mapstructure:"auto_config_firewall_rule" default:"false"`
	SniffingTimeout        time.Duration `mapstructure:"sniffing_timeout" default:"30ms"`
	TlsImplementation      string        `mapstructure:"tls_implementation" default:"tls"`
	UtlsImitate            string        `mapstructure:"utls_imitate" default:"chrome_auto"`
	TlsFragment            bool          `mapstructure:"tls_fragment" default:"false"`
	TlsFragmentLength      string        `mapstructure:"tls_fragment_length" default:"50-100"`
	TlsFragmentInterval    string        `mapstructure:"tls_fragment_interval" default:"10-20"`
	PprofPort              uint16        `mapstructure:"pprof_port" default:"0"`
	Mptcp                  bool          `mapstructure:"mptcp" default:"false"`
	BootstrapResolver      string        `mapstructure:"bootstrap_resolver"`
	FallbackResolver       string        `mapstructure:"fallback_resolver" default:"8.8.8.8:53"`
	BandwidthMaxTx         string        `mapstructure:"bandwidth_max_tx" default:"0"`
	BandwidthMaxRx         string        `mapstructure:"bandwidth_max_rx" default:"0"`
	UDPHopInterval         time.Duration `mapstructure:"udphop_interval" default:"30s"`
	BpfConnStateMapSize    uint32        `mapstructure:"bpf_conn_state_map_size" default:"262144"`
}

type Utls struct {
	Imitate string `mapstructure:"imitate"`
}

type FunctionOrString any

// ParseFunctionOrString converts a config value that may be either a string or
// a function into a single function without panicking on invalid input.
func ParseFunctionOrString(fs FunctionOrString) (*config_parser.Function, error) {
	switch fs := fs.(type) {
	case string:
		return &config_parser.Function{Name: fs}, nil
	case *config_parser.Function:
		return fs, nil
	case []*config_parser.Function:
		if len(fs) == 1 {
			return fs[0], nil
		}
		return nil, fmt.Errorf("expected exactly 1 function in fallback, got %d", len(fs))
	default:
		return nil, fmt.Errorf("unsupported function-or-string value type: %T", fs)
	}
}

// FunctionOrStringToFunction converts a function-or-string config value into a
// function. It preserves the historical panic-on-invalid-input API for external
// callers; new internal call sites should use ParseFunctionOrString.
func FunctionOrStringToFunction(fs FunctionOrString) *config_parser.Function {
	f, err := ParseFunctionOrString(fs)
	if err != nil {
		panic(err)
	}
	return f
}

type FunctionListOrString any

// ParseFunctionListOrString converts a config value that may be either a string
// or functions into a function list without panicking on invalid input.
func ParseFunctionListOrString(fs FunctionListOrString) ([]*config_parser.Function, error) {
	switch fs := fs.(type) {
	case string:
		return []*config_parser.Function{{Name: fs}}, nil
	case *config_parser.Function:
		return []*config_parser.Function{fs}, nil
	case []*config_parser.Function:
		return fs, nil
	default:
		return nil, fmt.Errorf("unsupported function-list-or-string value type: %T", fs)
	}
}

// FunctionListOrStringToFunctionList converts a function-list-or-string config
// value into a function list. It preserves the historical panic-on-invalid-input
// API for external callers; new internal call sites should use
// ParseFunctionListOrString.
func FunctionListOrStringToFunctionList(fs FunctionListOrString) []*config_parser.Function {
	f, err := ParseFunctionListOrString(fs)
	if err != nil {
		panic(err)
	}
	return f
}

type Group struct {
	Name string `mapstructure:"_"`

	Filter           [][]*config_parser.Function `mapstructure:"filter" repeatable:""`
	FilterAnnotation [][]*config_parser.Param    `mapstructure:"_"`
	Policy           FunctionListOrString        `mapstructure:"policy" required:""`

	TcpCheckUrl        []string      `mapstructure:"tcp_check_url"`
	TcpCheckHttpMethod string        `mapstructure:"tcp_check_http_method"`
	UdpCheckDns        []string      `mapstructure:"udp_check_dns"`
	CheckInterval      time.Duration `mapstructure:"check_interval"`
	CheckTolerance     time.Duration `mapstructure:"check_tolerance"`
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

// Dns is intentionally mirrored by cmd.dnsConfigFingerprint for staged reload
// DNS reuse decisions. Keep that fingerprint in sync with any new top-level
// fields; TestDNSConfigFingerprintCoversAllDnsFields guards the contract.
type Dns struct {
	IpVersionPrefer    int             `mapstructure:"ipversion_prefer"`
	FixedDomainTtl     []KeyableString `mapstructure:"fixed_domain_ttl"`
	Upstream           []KeyableString `mapstructure:"upstream"`
	Routing            DnsRouting      `mapstructure:"routing"`
	Bind               string          `mapstructure:"bind"`
	OptimisticCache    bool            `mapstructure:"optimistic_cache" default:"true"`
	OptimisticCacheTtl int             `mapstructure:"optimistic_cache_ttl" default:"60"`
	MaxCacheSize       int             `mapstructure:"max_cache_size" default:"0"`
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

func sectionHasParam(section *config_parser.Section, key string) bool {
	for _, item := range section.Items {
		param, ok := item.Value.(*config_parser.Param)
		if !ok {
			continue
		}
		if param.Key == key {
			return true
		}
	}
	return false
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
	for _, spec := range configSectionSpecs {
		if spec.required {
			if _, ok := nameToSection[spec.name]; !ok {
				return nil, fmt.Errorf("section %v is required but not provided", spec.name)
			}
		}
	}

	for _, spec := range configSectionSpecs {
		section, ok := nameToSection[spec.name]
		if !ok {
			continue
		}
		if err := decodeConfigSection(conf, spec.name, section.Val); err != nil {
			return nil, fmt.Errorf("failed to parse \"%v\": %w", spec.name, err)
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
