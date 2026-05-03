/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

func (c *ControlPlane) isRealDomain(domain string) bool {
	if known, real := c.lookupRealDomainCache(domain); known {
		return real
	}

	v, _, _ := c.realDomainProbeS.Do(domain, func() (any, error) {
		return c.probeAndUpdateRealDomain(domain), nil
	})
	isReal, _ := v.(bool)
	return isReal
}
