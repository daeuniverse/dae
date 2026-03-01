/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"errors"
	"fmt"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	_ "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

var ErrNoAliveDialer = fmt.Errorf("no alive dialer")

type DialerGroup struct {
	netproxy.Dialer

	log  *logrus.Logger
	Name string

	Dialers []*dialer.Dialer

	aliveDialerSets [6]*dialer.AliveDialerSet

	selectionPolicy *DialerSelectionPolicy
}

func NewDialerGroup(
	option *dialer.GlobalOption,
	name string,
	dialers []*dialer.Dialer,
	dialersAnnotations []*dialer.Annotation,
	p DialerSelectionPolicy,
	aliveChangeCallback func(alive bool, networkType *dialer.NetworkType, isInit bool),
) *DialerGroup {
	log := option.Log

	var needAliveState bool

	switch p.Policy {
	case consts.DialerSelectionPolicy_Random,
		consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		// Need to know the alive state or latency.
		needAliveState = true

	case consts.DialerSelectionPolicy_Fixed:
		// No need to know if the dialer is alive.
		needAliveState = false

	default:
		log.Panicf("Unexpected dialer selection policy: %v", p.Policy)
	}

	// networkTypeSpecs defines the 4 standard probe network types in the order
	// expected by aliveDialerSets (indices 0-3 map to DNS-TCP4/6, DNS-UDP4/6;
	// indices 4-5 map to TCP4/6 which are appended below).
	type networkTypeSpec struct {
		l4proto   consts.L4ProtoStr
		ipVersion consts.IpVersionStr
		isDns     bool
	}
	specs := [4]networkTypeSpec{
		// aliveDialerSets[IdxDnsTcp4..IdxDnsTcp6]: DNS-TCP sets (for CheckDnsTcp path – filled below).
		// aliveDialerSets[IdxDnsUdp4..IdxDnsUdp6]: DNS-UDP
		{consts.L4ProtoStr_UDP, consts.IpVersionStr_4, true},  // [2] aliveDnsUdp4
		{consts.L4ProtoStr_UDP, consts.IpVersionStr_6, true},  // [3] aliveDnsUdp6
		// aliveDialerSets[IdxTcp4..IdxTcp6]: plain TCP
		{consts.L4ProtoStr_TCP, consts.IpVersionStr_4, false}, // [4] aliveTcp4
		{consts.L4ProtoStr_TCP, consts.IpVersionStr_6, false}, // [5] aliveTcp6
	}

	// Indices within aliveDialerSets that correspond to specs[0..3].
	setIdx := [4]int{dialer.IdxDnsUdp4, dialer.IdxDnsUdp6, dialer.IdxTcp4, dialer.IdxTcp6}

	var aliveDialerSets [6]*dialer.AliveDialerSet

	for i, spec := range specs {
		nt := &dialer.NetworkType{
			L4Proto:   spec.l4proto,
			IpVersion: spec.ipVersion,
			IsDns:     spec.isDns,
		}
		if needAliveState {
			aliveDialerSets[setIdx[i]] = dialer.NewAliveDialerSet(
				log, name, nt, option.CheckTolerance, p.Policy, dialers, dialersAnnotations,
				func(networkType *dialer.NetworkType) func(alive bool) {
					// Use the trick to copy a pointer of *dialer.NetworkType.
					return func(alive bool) { aliveChangeCallback(alive, networkType, false) }
				}(nt), true)
		}
		aliveChangeCallback(true, nt, true)
	}

	if option.CheckDnsTcp && needAliveState {
		aliveDialerSets[dialer.IdxDnsTcp4] = dialer.NewAliveDialerSet(log, name, &dialer.NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_4,
			IsDns:     true,
		}, option.CheckTolerance, p.Policy, dialers, dialersAnnotations, func(alive bool) {}, true)

		aliveDialerSets[dialer.IdxDnsTcp6] = dialer.NewAliveDialerSet(log, name, &dialer.NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_6,
			IsDns:     true,
		}, option.CheckTolerance, p.Policy, dialers, dialersAnnotations, func(alive bool) {}, true)
	}

	for _, d := range dialers {
		for _, a := range aliveDialerSets {
			d.RegisterAliveDialerSet(a)
		}
	}

	return &DialerGroup{
		log:             log,
		Name:            name,
		Dialers:         dialers,
		aliveDialerSets: aliveDialerSets,
		selectionPolicy: &p,
	}

}

func (g *DialerGroup) Close() error {
	for _, d := range g.Dialers {
		for _, a := range g.aliveDialerSets {
			d.UnregisterAliveDialerSet(a)
		}
	}
	return nil
}

func (g *DialerGroup) SetSelectionPolicy(policy DialerSelectionPolicy) {
	g.selectionPolicy = &policy
}

func (g *DialerGroup) GetSelectionPolicy() (policy consts.DialerSelectionPolicy) {
	return g.selectionPolicy.Policy
}

func (d *DialerGroup) MustGetAliveDialerSet(typ *dialer.NetworkType) *dialer.AliveDialerSet {
	if typ.IsDns {
		switch typ.L4Proto {
		case consts.L4ProtoStr_TCP:
			switch typ.IpVersion {
			case consts.IpVersionStr_4:
				return d.aliveDialerSets[dialer.IdxDnsTcp4]
			case consts.IpVersionStr_6:
				return d.aliveDialerSets[dialer.IdxDnsTcp6]
			}
		case consts.L4ProtoStr_UDP:
			switch typ.IpVersion {
			case consts.IpVersionStr_4:
				return d.aliveDialerSets[dialer.IdxDnsUdp4]
			case consts.IpVersionStr_6:
				return d.aliveDialerSets[dialer.IdxDnsUdp6]
			}
		}
	} else {
		switch typ.L4Proto {
		case consts.L4ProtoStr_TCP:
			switch typ.IpVersion {
			case consts.IpVersionStr_4:
				return d.aliveDialerSets[dialer.IdxTcp4]
			case consts.IpVersionStr_6:
				return d.aliveDialerSets[dialer.IdxTcp6]
			}
		case consts.L4ProtoStr_UDP:
			// UDP share the DNS check result.
			switch typ.IpVersion {
			case consts.IpVersionStr_4:
				return d.aliveDialerSets[dialer.IdxDnsUdp4]
			case consts.IpVersionStr_6:
				return d.aliveDialerSets[dialer.IdxDnsUdp6]
			}
		}
	}
	panic("invalid param")
}

// Select selects a dialer from group according to selectionPolicy. If 'strictIpVersion' is false and no alive dialer, it will fallback to another ipversion.
func (g *DialerGroup) Select(networkType *dialer.NetworkType, strictIpVersion bool) (d *dialer.Dialer, latency time.Duration, err error) {
	policy := g.selectionPolicy
	d, latency, err = g._select(networkType, policy)
	if !strictIpVersion && errors.Is(err, ErrNoAliveDialer) {
		networkType.IpVersion = (consts.IpVersion_X - networkType.IpVersion.ToIpVersionType()).ToIpVersionStr()
		return g._select(networkType, policy)
	}
	if err == nil {
		return d, latency, nil
	}
	if errors.Is(err, ErrNoAliveDialer) && len(g.Dialers) == 1 {
		// There is only one dialer in this group. Just choose it instead of return error.
		if d, _, err = g._select(networkType, &DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 0,
		}); err != nil {
			return nil, 0, err
		}
		return d, dialer.Timeout, nil
	}
	return nil, latency, err
}

func (g *DialerGroup) _select(networkType *dialer.NetworkType, policy *DialerSelectionPolicy) (d *dialer.Dialer, latency time.Duration, err error) {
	if len(g.Dialers) == 0 {
		return nil, 0, fmt.Errorf("no dialer in this group")
	}
	a := g.MustGetAliveDialerSet(networkType)
	switch policy.Policy {
	case consts.DialerSelectionPolicy_Random:
		d := a.GetRand()
		if d == nil {
			// No alive dialer.
			return nil, time.Hour, ErrNoAliveDialer
		}
		return d, 0, nil

	case consts.DialerSelectionPolicy_Fixed:
		if g.selectionPolicy.FixedIndex < 0 || g.selectionPolicy.FixedIndex >= len(g.Dialers) {
			return nil, 0, fmt.Errorf("selected dialer index is out of range")
		}
		return g.Dialers[g.selectionPolicy.FixedIndex], 0, nil

	case consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		d, latency := a.GetMinLatency()
		if d == nil {
			// No alive dialer.
			return nil, time.Hour, ErrNoAliveDialer
		}
		return d, latency, nil

	default:
		return nil, 0, fmt.Errorf("unsupported DialerSelectionPolicy: %v", g.selectionPolicy)
	}
}
