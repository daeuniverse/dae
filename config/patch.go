/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package config

import "fmt"

type patch func(params *Params) error

var patches = []patch{
	patchRoutingFallback,
}

func patchRoutingFallback(params *Params) error {
	// We renamed final as fallback. So we apply this patch for compatibility with older users.
	if params.Routing.Fallback == "" && params.Routing.Final != "" {
		params.Routing.Fallback = params.Routing.Final
	}
	// Fallback is required.
	if params.Routing.Fallback == "" {
		return fmt.Errorf("fallback is required in routing")
	}
	return nil
}
