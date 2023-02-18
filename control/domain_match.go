/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"github.com/v2rayA/dae/common/consts"
	"regexp"
	"strings"
)

func (c *ControlPlane) MatchDomainBitmap(domain string) (bitmap [consts.MaxMatchSetLen / 32]uint32) {
	// TODO: high performance implementation.
	for _, s := range c.SimulatedDomainSet {
		for _, d := range s.Domains {
			var hit bool
			switch s.Key {
			case consts.RoutingDomain_Suffix:
				if domain == d || strings.HasSuffix(domain, "."+d) {
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
				// FIXME: too slow
				for _, d := range s.Domains {
					if regexp.MustCompile(d).MatchString(strings.ToLower(domain)) {
						hit = true
						break
					}
				}
			}
			if hit {
				bitmap[s.RuleIndex/32] |= 1 << (s.RuleIndex % 32)
				break
			}
		}
	}
	return bitmap
}
