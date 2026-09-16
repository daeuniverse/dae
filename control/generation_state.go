/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/routing"
)

type controlPlaneGenerationState struct {
	outbounds           []*outbound.DialerGroup
	referencedOutbounds map[string]struct{}
	dialMode            consts.DialMode
	policyIdentity      routing.PolicyIdentity
	routingMatcher      *RoutingMatcher
	bootstrapResolvers  []netip.AddrPort
}
