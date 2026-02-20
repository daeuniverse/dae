/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"github.com/daeuniverse/dae/common"
	"github.com/sirupsen/logrus"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type patch func(params *Config) error

var patches = []patch{
	patchTcpCheckHttpMethod,
	patchEmptyDns,
	patchDnsPerformanceLevel,
	patchMustOutbound,
}

func patchTcpCheckHttpMethod(params *Config) error {
	if !common.IsValidHttpMethod(params.Global.TcpCheckHttpMethod) {
		logrus.Warnf("Unknown HTTP Method '%v'. Fallback to 'CONNECT'.", params.Global.TcpCheckHttpMethod)
		params.Global.TcpCheckHttpMethod = "CONNECT"
	}
	return nil
}

func patchEmptyDns(params *Config) error {
	if params.Dns.Routing.Request.Fallback == nil {
		params.Dns.Routing.Request.Fallback = consts.DnsRequestOutboundIndex_AsIs.String()
	}
	if params.Dns.Routing.Response.Fallback == nil {
		params.Dns.Routing.Response.Fallback = consts.DnsResponseOutboundIndex_Accept.String()
	}
	return nil
}

func patchDnsPerformanceLevel(params *Config) error {
	level := strings.ToLower(strings.TrimSpace(params.Global.DnsPerformanceLevel))
	switch level {
	case "lean", "balanced", "aggressive", "manual":
		params.Global.DnsPerformanceLevel = level
	case "":
		params.Global.DnsPerformanceLevel = "balanced"
	default:
		logrus.Warnf("Unknown dns_performance_level '%s', falling back to 'balanced'", params.Global.DnsPerformanceLevel)
		params.Global.DnsPerformanceLevel = "balanced"
	}

	if params.Global.DnsPerformanceLevel == "manual" {
		m := &params.Global.DnsIngressManual
		const minW, maxW uint16 = 32, 1024
		const minQ, maxQ uint16 = 128, 16384
		if m.Workers == 0 {
			m.Workers = 256
		}
		if m.Queue == 0 {
			m.Queue = 2048
		}
		if m.Workers < minW {
			logrus.Warnf("dns_ingress_manual.workers %d below min %d, clamping", m.Workers, minW)
			m.Workers = minW
		} else if m.Workers > maxW {
			logrus.Warnf("dns_ingress_manual.workers %d above max %d, clamping", m.Workers, maxW)
			m.Workers = maxW
		}
		if m.Queue < minQ {
			logrus.Warnf("dns_ingress_manual.queue %d below min %d, clamping", m.Queue, minQ)
			m.Queue = minQ
		} else if m.Queue > maxQ {
			logrus.Warnf("dns_ingress_manual.queue %d above max %d, clamping", m.Queue, maxQ)
			m.Queue = maxQ
		}
	}
	return nil
}

func patchMustOutbound(params *Config) error {
	for i := range params.Routing.Rules {
		if strings.HasPrefix(params.Routing.Rules[i].Outbound.Name, "must_") {
			if params.Routing.Rules[i].Outbound.Name == "must_rules" {
				// Reserve must_rules.
				continue
			}
			params.Routing.Rules[i].Outbound.Name = strings.TrimPrefix(params.Routing.Rules[i].Outbound.Name, "must_")
			params.Routing.Rules[i].Outbound.Params = append(params.Routing.Rules[i].Outbound.Params, &config_parser.Param{
				Val: "must",
			})
		}
	}
	if f := FunctionOrStringToFunction(params.Routing.Fallback); strings.HasPrefix(f.Name, "must_") {
		f.Name = strings.TrimPrefix(f.Name, "must_")
		f.Params = append(f.Params, &config_parser.Param{
			Val: "must",
		})
		params.Routing.Fallback = f
	}
	return nil
}
