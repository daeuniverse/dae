/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package routing

import (
	"fmt"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/pkg/config_parser"
	"net/netip"
	"strings"
)

var FakeOutbound_AND = consts.OutboundLogicalAnd.String()

type MatcherBuilder interface {
	AddDomain(key string, values []string, outbound string)
	AddIp(values []netip.Prefix, outbound string)
	AddPort(values [][2]int, outbound string)
	AddSourceIp(values []netip.Prefix, outbound string)
	AddSourcePort(values [][2]int, outbound string)
	AddL4Proto(values consts.L4ProtoType, outbound string)
	AddIpVersion(values consts.IpVersion, outbound string)
	AddSourceMac(values [][6]byte, outbound string)
	AddFinal(outbound string)
	AddAnyBefore(function string, key string, values []string, outbound string)
	AddAnyAfter(function string, key string, values []string, outbound string)
	Build() (err error)
}

func GroupParamValuesByKey(params []*config_parser.Param) map[string][]string {
	groups := make(map[string][]string)
	for _, param := range params {
		groups[param.Key] = append(groups[param.Key], param.Val)
	}
	return groups
}

func ParsePrefixes(values []string) (cidrs []netip.Prefix, err error) {
	for _, value := range values {
		toParse := value
		if strings.LastIndexByte(value, '/') == -1 {
			toParse += "/32"
		}
		prefix, err := netip.ParsePrefix(toParse)
		if err != nil {
			return nil, fmt.Errorf("cannot parse %v: %w", value, err)
		}
		cidrs = append(cidrs, prefix)
	}
	return cidrs, nil
}

func ApplyMatcherBuilder(builder MatcherBuilder, rules []*config_parser.RoutingRule, finalOutbound string) (err error) {
	for _, rule := range rules {
		// rule is like: domain(domain:baidu.com) && port(443) -> proxy
		for iFunc, f := range rule.AndFunctions {
			// f is like: domain(domain:baidu.com)
			paramValueGroups := GroupParamValuesByKey(f.Params)
			for key, paramValueGroup := range paramValueGroups {
				// Preprocess the outbound and pass FakeOutbound_AND to all but the last function.
				outbound := FakeOutbound_AND
				if iFunc == len(rule.AndFunctions)-1 {
					outbound = rule.Outbound
				}
				builder.AddAnyBefore(f.Name, key, paramValueGroup, outbound)
				switch f.Name {
				case consts.Function_Domain:
					builder.AddDomain(key, paramValueGroup, outbound)
				case consts.Function_Ip, consts.Function_SourceIp:
					cidrs, err := ParsePrefixes(paramValueGroup)
					if err != nil {
						return err
					}
					if f.Name == consts.Function_Ip {
						builder.AddIp(cidrs, outbound)
					} else {
						builder.AddSourceIp(cidrs, outbound)
					}
				case consts.Function_Mac:
					var macAddrs [][6]byte
					for _, v := range paramValueGroup {
						mac, err := common.ParseMac(v)
						if err != nil {
							return err
						}
						macAddrs = append(macAddrs, mac)
					}
					builder.AddSourceMac(macAddrs, outbound)
				case consts.Function_Port, consts.Function_SourcePort:
					var portRanges [][2]int
					for _, v := range paramValueGroup {
						portRange, err := common.ParsePortRange(v)
						if err != nil {
							return err
						}
						portRanges = append(portRanges, portRange)
					}
					if f.Name == consts.Function_Port {
						builder.AddPort(portRanges, outbound)
					} else {
						builder.AddSourcePort(portRanges, outbound)
					}
				case consts.Function_L4Proto:
					var l4protoType consts.L4ProtoType
					for _, v := range paramValueGroup {
						switch v {
						case "tcp":
							l4protoType |= consts.L4ProtoType_TCP
						case "udp":
							l4protoType |= consts.L4ProtoType_UDP
						}
					}
					builder.AddL4Proto(l4protoType, outbound)
				case consts.Function_IpVersion:
					var ipVersion consts.IpVersion
					for _, v := range paramValueGroup {
						switch v {
						case "4":
							ipVersion |= consts.IpVersion_4
						case "6":
							ipVersion |= consts.IpVersion_6
						}
					}
					builder.AddIpVersion(ipVersion, outbound)
				default:
					return fmt.Errorf("unsupported function name: %v", f.Name)
				}
				builder.AddAnyAfter(f.Name, key, paramValueGroup, outbound)
			}
		}
	}
	builder.AddAnyBefore("final", "", nil, finalOutbound)
	builder.AddFinal(finalOutbound)
	builder.AddAnyAfter("final", "", nil, finalOutbound)
	return nil
}

type DefaultMatcherBuilder struct{}

func (d *DefaultMatcherBuilder) AddDomain(values []string, outbound string)            {}
func (d *DefaultMatcherBuilder) AddIp(values []netip.Prefix, outbound string)          {}
func (d *DefaultMatcherBuilder) AddPort(values [][2]int, outbound string)              {}
func (d *DefaultMatcherBuilder) AddSource(values []netip.Prefix, outbound string)      {}
func (d *DefaultMatcherBuilder) AddSourcePort(values [][2]int, outbound string)        {}
func (d *DefaultMatcherBuilder) AddL4Proto(values consts.L4ProtoType, outbound string) {}
func (d *DefaultMatcherBuilder) AddIpVersion(values consts.IpVersion, outbound string) {}
func (d *DefaultMatcherBuilder) AddMac(values [][6]byte, outbound string)              {}
func (d *DefaultMatcherBuilder) AddFinal(outbound string)                              {}
func (d *DefaultMatcherBuilder) AddAnyBefore(function string, key string, values []string, outbound string) {
}
func (d *DefaultMatcherBuilder) AddAnyAfter(function string, key string, values []string, outbound string) {
}
func (d *DefaultMatcherBuilder) Build() (err error) { return nil }
