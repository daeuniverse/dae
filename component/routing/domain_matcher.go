/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, v2rayA Organization <team@v2raya.org>
 */

package routing

import "github.com/v2rayA/dae/common/consts"

type DomainMatcher interface {
	AddSet(bitIndex int, patterns []string, typ consts.RoutingDomainKey)
	Build() error
	MatchDomainBitmap(domain string) (bitmap []uint32)
}
