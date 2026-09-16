/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/routing"
)

// UdpRouteBinding records the immutable policy result selected for a UDP endpoint.
type UdpRouteBinding struct {
	PolicyEpoch routing.PolicyEpoch
	Outbound    consts.OutboundIndex
	Mark        uint32
	Must        bool
}

// UdpEgressBinding records the concrete transport selection for a UDP endpoint.
// It is intentionally distinct from UdpRouteBinding because dialer health may
// affect a new selection without rewriting the policy chosen for a live flow.
type UdpEgressBinding struct {
	Dialer        *dialer.Dialer
	Outbound      *outbound.DialerGroup
	Target        string
	Network       string
	NetworkType   dialer.NetworkType
	SniffedDomain string
	IsDialIp      bool
}

// UdpFlowBinding combines the policy and egress decisions fixed at endpoint creation.
type UdpFlowBinding struct {
	Route  UdpRouteBinding
	Egress UdpEgressBinding
}

func newUdpFlowBinding(policyEpoch routing.PolicyEpoch, outboundIndex consts.OutboundIndex, mark uint32, must bool, option *DialOption) UdpFlowBinding {
	binding := UdpFlowBinding{
		Route: UdpRouteBinding{
			PolicyEpoch: policyEpoch,
			Outbound:    outboundIndex,
			Mark:        mark,
			Must:        must,
		},
	}
	if option == nil {
		return binding
	}
	binding.Egress = UdpEgressBinding{
		Dialer:        option.Dialer,
		Outbound:      option.Outbound,
		Target:        option.Target,
		Network:       option.Network,
		SniffedDomain: option.SniffedDomain,
		IsDialIp:      option.IsDialIp,
	}
	if option.NetworkType != nil {
		binding.Egress.NetworkType = *option.NetworkType
	}
	return binding
}
