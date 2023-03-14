/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import "github.com/daeuniverse/dae/common/consts"

type DomainMatcher interface {
	AddSet(bitIndex int, patterns []string, typ consts.RoutingDomainKey)
	Build() error
	MatchDomainBitmap(domain string) (bitmap []uint32)
}
