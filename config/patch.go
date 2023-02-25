/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package config

import (
	"fmt"
	"github.com/v2rayA/dae/common/consts"
)

type patch func(params *Config) error

var patches = []patch{
	patchEmptyDns,
	patchDeprecatedGlobalDnsUpstream,
	patchDeprecatedLanNatDirect,
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

func patchDeprecatedGlobalDnsUpstream(params *Config) error {
	if params.Global.DnsUpstream != "<empty>" {
		return fmt.Errorf("'global.dns_upstream' was deprecated, please refer to the latest examples and docs for help")
	}
	params.Global.DnsUpstream = ""
	return nil
}

func patchDeprecatedLanNatDirect(params *Config) error {
	if params.Global.LanNatDirect != false {
		return fmt.Errorf("'global.lan_nat_direct' was deprecated; please remove it")
	}
	return nil
}
