/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package routing

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/pkg/config_parser"
	"net/netip"
	"strings"
)

var FakeOutbound_MUST_DIRECT = consts.OutboundMustDirect.String()
var FakeOutbound_AND = consts.OutboundLogicalAnd.String()
var FakeOutbound_OR = consts.OutboundLogicalOr.String()

type DomainSet struct {
	Key       consts.RoutingDomainKey
	RuleIndex int
	Domains   []string
}

type MatcherBuilder interface {
	AddDomain(f *config_parser.Function, key string, values []string, outbound string)
	AddIp(f *config_parser.Function, values []netip.Prefix, outbound string)
	AddPort(f *config_parser.Function, values [][2]uint16, outbound string)
	AddSourceIp(f *config_parser.Function, values []netip.Prefix, outbound string)
	AddSourcePort(f *config_parser.Function, values [][2]uint16, outbound string)
	AddL4Proto(f *config_parser.Function, values consts.L4ProtoType, outbound string)
	AddIpVersion(f *config_parser.Function, values consts.IpVersionType, outbound string)
	AddSourceMac(f *config_parser.Function, values [][6]byte, outbound string)
	AddProcessName(f *config_parser.Function, values [][consts.TaskCommLen]byte, outbound string)
	AddFallback(outbound string)
	AddAnyBefore(f *config_parser.Function, key string, values []string, outbound string)
	AddAnyAfter(f *config_parser.Function, key string, values []string, outbound string)
}

func GroupParamValuesByKey(params []*config_parser.Param) (keyToValues map[string][]string, keyOrder []string) {
	groups := make(map[string][]string)
	for _, param := range params {
		if _, ok := groups[param.Key]; !ok {
			keyOrder = append(keyOrder, param.Key)
		}
		groups[param.Key] = append(groups[param.Key], param.Val)
	}
	return groups, keyOrder
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

func ToProcessName(processName string) (procName [consts.TaskCommLen]byte) {
	n := []byte(processName)
	copy(procName[:], n)
	return procName
}

func ApplyMatcherBuilder(log *logrus.Logger, builder MatcherBuilder, rules []*config_parser.RoutingRule, fallbackOutbound string) (err error) {
	for _, rule := range rules {
		log.Debugln("[rule]", rule.String(true))

		// rule is like: domain(domain:baidu.com) && port(443) -> proxy
		for iFunc, f := range rule.AndFunctions {
			// f is like: domain(domain:baidu.com)
			paramValueGroups, keyOrder := GroupParamValuesByKey(f.Params)
			for jMatchSet, key := range keyOrder {
				paramValueGroup := paramValueGroups[key]
				// Preprocess the outbound and pass FakeOutbound_AND to all but the last function.
				outbound := FakeOutbound_OR
				if jMatchSet == len(keyOrder)-1 {
					outbound = FakeOutbound_AND
					if iFunc == len(rule.AndFunctions)-1 {
						outbound = rule.Outbound
					}
				}

				{
					// Debug
					symNot := ""
					if f.Not {
						symNot = "!"
					}
					log.Debugf("\t%v%v(%v) -> %v", symNot, f.Name, key, outbound)
				}

				builder.AddAnyBefore(f, key, paramValueGroup, outbound)
				switch f.Name {
				case consts.Function_Domain:
					builder.AddDomain(f, key, paramValueGroup, outbound)
				case consts.Function_Ip, consts.Function_SourceIp:
					cidrs, err := ParsePrefixes(paramValueGroup)
					if err != nil {
						return err
					}
					if f.Name == consts.Function_Ip {
						builder.AddIp(f, cidrs, outbound)
					} else {
						builder.AddSourceIp(f, cidrs, outbound)
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
					builder.AddSourceMac(f, macAddrs, outbound)
				case consts.Function_Port, consts.Function_SourcePort:
					var portRanges [][2]uint16
					for _, v := range paramValueGroup {
						portRange, err := common.ParsePortRange(v)
						if err != nil {
							return err
						}
						portRanges = append(portRanges, portRange)
					}
					if f.Name == consts.Function_Port {
						builder.AddPort(f, portRanges, outbound)
					} else {
						builder.AddSourcePort(f, portRanges, outbound)
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
					builder.AddL4Proto(f, l4protoType, outbound)
				case consts.Function_IpVersion:
					var ipVersion consts.IpVersionType
					for _, v := range paramValueGroup {
						switch v {
						case "4":
							ipVersion |= consts.IpVersion_4
						case "6":
							ipVersion |= consts.IpVersion_6
						}
					}
					builder.AddIpVersion(f, ipVersion, outbound)
				case consts.Function_ProcessName:
					var procNames [][consts.TaskCommLen]byte
					for _, v := range paramValueGroup {
						if len([]byte(v)) > consts.TaskCommLen {
							log.Infof(`pname routing: trim "%v" to "%v" because it is too long.`, v, string([]byte(v)[:consts.TaskCommLen]))
						}
						procNames = append(procNames, ToProcessName(v))
					}
					builder.AddProcessName(f, procNames, outbound)
				default:
					return fmt.Errorf("unsupported function name: %v", f.Name)
				}
				builder.AddAnyAfter(f, key, paramValueGroup, outbound)
			}
		}
	}
	builder.AddAnyBefore(&config_parser.Function{
		Name: "fallback",
	}, "", nil, fallbackOutbound)
	builder.AddFallback(fallbackOutbound)
	builder.AddAnyAfter(&config_parser.Function{
		Name: "fallback",
	}, "", nil, fallbackOutbound)
	return nil
}

type DefaultMatcherBuilder struct {
}

func (d *DefaultMatcherBuilder) AddDomain(f *config_parser.Function, key string, values []string, outbound string) {
}
func (d *DefaultMatcherBuilder) AddIp(f *config_parser.Function, values []netip.Prefix, outbound string) {
}
func (d *DefaultMatcherBuilder) AddPort(f *config_parser.Function, values [][2]uint16, outbound string) {
}
func (d *DefaultMatcherBuilder) AddSourceIp(f *config_parser.Function, values []netip.Prefix, outbound string) {
}
func (d *DefaultMatcherBuilder) AddSourcePort(f *config_parser.Function, values [][2]uint16, outbound string) {
}
func (d *DefaultMatcherBuilder) AddL4Proto(f *config_parser.Function, values consts.L4ProtoType, outbound string) {
}
func (d *DefaultMatcherBuilder) AddIpVersion(f *config_parser.Function, values consts.IpVersionType, outbound string) {
}
func (d *DefaultMatcherBuilder) AddSourceMac(f *config_parser.Function, values [][6]byte, outbound string) {
}
func (d *DefaultMatcherBuilder) AddFallback(outbound string) {}
func (d *DefaultMatcherBuilder) AddAnyBefore(f *config_parser.Function, key string, values []string, outbound string) {
}
func (d *DefaultMatcherBuilder) AddProcessName(f *config_parser.Function, values [][consts.TaskCommLen]byte, outbound string) {
}
func (d *DefaultMatcherBuilder) AddAnyAfter(f *config_parser.Function, key string, values []string, outbound string) {
}
