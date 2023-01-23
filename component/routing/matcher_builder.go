/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package routing

import (
	"fmt"
	consts2 "foo/common/consts"
	"net/netip"
	"strings"
)

var FakeOutbound_AND = consts2.OutboundLogicalAnd.String()

type MatcherBuilder interface {
	AddDomain(key string, values []string, outbound string)
	AddIp(values []netip.Prefix, outbound string)
	AddPort(values [][2]int, outbound string)
	AddSource(values []netip.Prefix, outbound string)
	AddSourcePort(values [][2]int, outbound string)
	AddNetwork(values consts2.NetworkType, outbound string)
	AddIpVersion(values consts2.IpVersion, outbound string)
	AddMac(values [][6]byte, outbound string)
	AddFinal(outbound string)
	AddAnyBefore(key string, values []string, outbound string)
	AddAnyAfter(key string, values []string, outbound string)
	Build() (err error)
}

func GroupParamValuesByKey(params []*Param) map[string][]string {
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

func ApplyMatcherBuilder(builder MatcherBuilder, rules []RoutingRule, finalOutbound string) (err error) {
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
				builder.AddAnyBefore(key, paramValueGroup, outbound)
				switch f.Name {
				case "domain":
					builder.AddDomain(key, paramValueGroup, outbound)
				case "ip":
					cidrs, err := ParsePrefixes(paramValueGroup)
					if err != nil {
						return err
					}
					builder.AddIp(cidrs, outbound)
				}
				builder.AddAnyAfter(key, paramValueGroup, outbound)
			}
		}
	}
	builder.AddAnyBefore("", nil, finalOutbound)
	builder.AddFinal(finalOutbound)
	builder.AddAnyAfter("", nil, finalOutbound)
	return nil
}

type DefaultMatcherBuilder struct{}

func (d *DefaultMatcherBuilder) AddDomain(values []string, outbound string)                {}
func (d *DefaultMatcherBuilder) AddIp(values []netip.Prefix, outbound string)              {}
func (d *DefaultMatcherBuilder) AddPort(values [][2]int, outbound string)                  {}
func (d *DefaultMatcherBuilder) AddSource(values []netip.Prefix, outbound string)          {}
func (d *DefaultMatcherBuilder) AddSourcePort(values [][2]int, outbound string)            {}
func (d *DefaultMatcherBuilder) AddNetwork(values consts2.NetworkType, outbound string)    {}
func (d *DefaultMatcherBuilder) AddIpVersion(values consts2.IpVersion, outbound string)    {}
func (d *DefaultMatcherBuilder) AddMac(values [][6]byte, outbound string)                  {}
func (d *DefaultMatcherBuilder) AddFinal(outbound string)                                  {}
func (d *DefaultMatcherBuilder) AddAnyBefore(key string, values []string, outbound string) {}
func (d *DefaultMatcherBuilder) AddAnyAfter(key string, values []string, outbound string)  {}
func (d *DefaultMatcherBuilder) Build() (err error)                                        { return nil }
