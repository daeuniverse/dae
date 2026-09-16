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

// TcpRouteBinding records the immutable policy result selected for a TCP connection.
type TcpRouteBinding struct {
	PolicyEpoch routing.PolicyEpoch
	Outbound    consts.OutboundIndex
	Mark        uint32
	Must        bool
}

// TcpEgressBinding records the concrete transport selection for a TCP connection.
// It is intentionally distinct from TcpRouteBinding because dialer health may
// affect a new selection without rewriting the policy chosen for a live connection.
type TcpEgressBinding struct {
	Dialer        *dialer.Dialer
	Outbound      *outbound.DialerGroup
	Target        string
	Network       string
	NetworkType   dialer.NetworkType
	SniffedDomain string
	IsDialIp      bool
}

// TcpFlowBinding combines the policy and egress decisions fixed after a TCP dial succeeds.
type TcpFlowBinding struct {
	Route  TcpRouteBinding
	Egress TcpEgressBinding
}

func newTcpFlowBinding(policyEpoch routing.PolicyEpoch, result *proxyDialResult) TcpFlowBinding {
	binding := TcpFlowBinding{}
	binding.Route.PolicyEpoch = policyEpoch
	if result == nil {
		return binding
	}
	binding.Route.Outbound = result.OutboundIndex
	binding.Route.Mark = result.Mark
	binding.Route.Must = result.Must
	binding.Egress = TcpEgressBinding{
		Dialer:        result.Dialer,
		Outbound:      result.Outbound,
		Target:        result.DialTarget,
		Network:       result.Network,
		SniffedDomain: result.SniffedDomain,
		IsDialIp:      result.IsDialIp,
	}
	if result.SelectionNetworkTypeObj != nil {
		binding.Egress.NetworkType = *result.SelectionNetworkTypeObj
	}
	return binding
}
