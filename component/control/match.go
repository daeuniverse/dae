/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package control

import (
	"github.com/v2rayA/dae/common/consts"
	"strings"
)

func (c *ControlPlane) MatchDomainBitmap(domain string) (bitmap [consts.MaxRoutingLen / 32]uint32) {
	// FIXME: high performance implementation.
	for _, s := range c.SimulatedDomainSet {
		for _, d := range s.Domains {
			var hit bool
			switch s.Key {
			case consts.RoutingDomain_Suffix:
				if strings.HasSuffix(domain, d) {
					hit = true
				}
			case consts.RoutingDomain_Full:
				if strings.EqualFold(domain, d) {
					hit = true
				}
			case consts.RoutingDomain_Keyword:
				if strings.Contains(strings.ToLower(domain), strings.ToLower(d)) {
					hit = true
				}
			case consts.RoutingDomain_Regex:
				c.log.Warnln("MatchDomainBitmap does not support regex yet")
			}
			if hit {
				bitmap[s.RuleIndex/32] |= 1 << (s.RuleIndex % 32)
				break
			}
		}
	}
	return bitmap
}
