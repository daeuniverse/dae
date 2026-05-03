/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
)

type controlPlaneGenerationState struct {
	outbounds           []*outbound.DialerGroup
	referencedOutbounds map[string]struct{}
	dialMode            consts.DialMode
	routingMatcher      *RoutingMatcher
	bootstrapResolvers  []netip.AddrPort
}

func (s *controlPlaneGenerationState) releaseRetainedState() {
	if s == nil {
		return
	}
	s.outbounds = nil
	s.referencedOutbounds = nil
	s.routingMatcher = nil
	s.bootstrapResolvers = nil
}
