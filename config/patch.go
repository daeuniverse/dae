/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/sirupsen/logrus"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type patch func(params *Config) error

var patches = []patch{
	patchBootstrapResolver,
	patchCheckInterval,
	patchTcpCheckHttpMethod,
	patchEmptyDns,
	patchMustOutbound,
}

func patchBootstrapResolver(params *Config) error {
	_, err := BootstrapResolvers(&params.Global)
	return err
}

func patchTcpCheckHttpMethod(params *Config) error {
	if !common.IsValidHttpMethod(params.Global.TcpCheckHttpMethod) {
		logrus.Warnf("Unknown HTTP Method '%v'. Fallback to 'CONNECT'.", params.Global.TcpCheckHttpMethod)
		params.Global.TcpCheckHttpMethod = "CONNECT"
	}
	return nil
}

// patchCheckInterval rejects intervals that can panic the connectivity check
// scheduler when passed to the random phase spread.
func patchCheckInterval(params *Config) error {
	if params.Global.CheckInterval <= 0 {
		return fmt.Errorf(
			"global check_interval must be a positive duration (got \"%v\")",
			params.Global.CheckInterval)
	}
	for _, group := range params.Group {
		// Zero means inherit the validated global interval.
		if group.CheckInterval < 0 {
			return fmt.Errorf(
				"group %q check_interval must not be negative (got \"%v\")",
				group.Name, group.CheckInterval)
		}
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
	f, err := ParseFunctionOrString(params.Routing.Fallback)
	if err != nil {
		return err
	}
	if after, ok := strings.CutPrefix(f.Name, "must_"); ok {
		f.Name = after
		f.Params = append(f.Params, &config_parser.Param{
			Val: "must",
		})
		params.Routing.Fallback = f
	}
	return nil
}
