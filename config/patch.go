/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package config

import (
	"fmt"
	"github.com/sirupsen/logrus"
)

type patch func(params *Params) error

var patches = []patch{
	patchRoutingFallback,
}

func patchRoutingFallback(params *Params) error {
	// We renamed final as fallback. So we apply this patch for compatibility with older users.
	if params.Routing.Fallback == nil && params.Routing.Final != nil {
		params.Routing.Fallback = params.Routing.Final
		logrus.Warnln("Name 'final' in section routing was deprecated and will be removed in the future; please rename it as 'fallback'")
	}
	// Fallback is required.
	if params.Routing.Fallback == nil {
		return fmt.Errorf("fallback is required in routing")
	}
	return nil
}
