/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
)

type patch func(params *Config) error

var patches = []patch{
	patchEmptyDns,
	patchWanInterfaceAuto,
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

func patchWanInterfaceAuto(params *Config) error {
	// preprocess "auto".
	ifs := make([]string, 0, len(params.Global.WanInterface)+2)
	for _, ifname := range params.Global.WanInterface {
		if ifname == "auto" {
			defaultIfs, err := common.GetDefaultIfnames()
			if err != nil {
				return fmt.Errorf("failed to convert 'auto': %w", err)
			}
			ifs = append(ifs, defaultIfs...)
		} else {
			ifs = append(ifs, ifname)
		}
	}
	params.Global.WanInterface = common.Deduplicate(ifs)
	return nil
}
