/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package outbound

import (
	"fmt"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/component/outbound/dialer"
	"time"
)

var NoAliveDialerError = fmt.Errorf("no alive dialer")

type DialerGroup struct {
	netproxy.Dialer

	log  *logrus.Logger
	Name string

	Dialers []*dialer.Dialer

	aliveDialerSets [6]*dialer.AliveDialerSet

	selectionPolicy *DialerSelectionPolicy
}

func NewDialerGroup(option *dialer.GlobalOption, name string, dialers []*dialer.Dialer, p DialerSelectionPolicy, aliveChangeCallback func(alive bool, networkType *dialer.NetworkType)) *DialerGroup {
	log := option.Log
	var aliveDnsTcp4DialerSet *dialer.AliveDialerSet
	var aliveDnsTcp6DialerSet *dialer.AliveDialerSet
	var aliveTcp4DialerSet *dialer.AliveDialerSet
	var aliveTcp6DialerSet *dialer.AliveDialerSet
	var aliveDnsUdp4DialerSet *dialer.AliveDialerSet
	var aliveDnsUdp6DialerSet *dialer.AliveDialerSet

	switch p.Policy {
	case consts.DialerSelectionPolicy_Random,
		consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies:

		// Need to know the alive state or latency.
		networkType := &dialer.NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_4,
			IsDns:     false,
		}
		aliveTcp4DialerSet = dialer.NewAliveDialerSet(
			log, name, networkType, option.CheckTolerance, p.Policy, dialers,
			func(networkType *dialer.NetworkType) func(alive bool) {
				// Use the trick to copy a pointer of *dialer.NetworkType.
				return func(alive bool) { aliveChangeCallback(alive, networkType) }
			}(networkType), true)

		networkType = &dialer.NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_6,
			IsDns:     false,
		}
		aliveTcp6DialerSet = dialer.NewAliveDialerSet(
			log, name, networkType, option.CheckTolerance, p.Policy, dialers,
			func(networkType *dialer.NetworkType) func(alive bool) {
				// Use the trick to copy a pointer of *dialer.NetworkType.
				return func(alive bool) { aliveChangeCallback(alive, networkType) }
			}(networkType), true)

		networkType = &dialer.NetworkType{
			L4Proto:   consts.L4ProtoStr_UDP,
			IpVersion: consts.IpVersionStr_4,
			IsDns:     true,
		}
		aliveDnsUdp4DialerSet = dialer.NewAliveDialerSet(
			log, name, networkType, option.CheckTolerance, p.Policy, dialers,
			func(networkType *dialer.NetworkType) func(alive bool) {
				// Use the trick to copy a pointer of *dialer.NetworkType.
				return func(alive bool) { aliveChangeCallback(alive, networkType) }
			}(networkType), true)

		networkType = &dialer.NetworkType{
			L4Proto:   consts.L4ProtoStr_UDP,
			IpVersion: consts.IpVersionStr_6,
			IsDns:     true,
		}
		aliveDnsUdp6DialerSet = dialer.NewAliveDialerSet(
			log, name, networkType, option.CheckTolerance, p.Policy, dialers,
			func(networkType *dialer.NetworkType) func(alive bool) {
				// Use the trick to copy a pointer of *dialer.NetworkType.
				return func(alive bool) { aliveChangeCallback(alive, networkType) }
			}(networkType), true)

		if option.CheckDnsTcp {
			aliveDnsTcp4DialerSet = dialer.NewAliveDialerSet(log, name, &dialer.NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_4,
				IsDns:     true,
			}, option.CheckTolerance, p.Policy, dialers, func(alive bool) {}, true)

			aliveDnsTcp6DialerSet = dialer.NewAliveDialerSet(log, name, &dialer.NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_6,
				IsDns:     true,
			}, option.CheckTolerance, p.Policy, dialers, func(alive bool) {}, true)
		}

	case consts.DialerSelectionPolicy_Fixed:
		// No need to know if the dialer is alive.

	default:
		log.Panicf("Unexpected dialer selection policy: %v", p.Policy)
	}

	for _, d := range dialers {
		d.RegisterAliveDialerSet(aliveTcp4DialerSet)
		d.RegisterAliveDialerSet(aliveTcp6DialerSet)
		d.RegisterAliveDialerSet(aliveDnsTcp4DialerSet)
		d.RegisterAliveDialerSet(aliveDnsTcp6DialerSet)
		d.RegisterAliveDialerSet(aliveDnsUdp4DialerSet)
		d.RegisterAliveDialerSet(aliveDnsUdp6DialerSet)
	}

	return &DialerGroup{
		log:     log,
		Name:    name,
		Dialers: dialers,
		aliveDialerSets: [6]*dialer.AliveDialerSet{
			aliveDnsTcp4DialerSet,
			aliveDnsTcp6DialerSet,
			aliveDnsUdp4DialerSet,
			aliveDnsUdp6DialerSet,
			aliveTcp4DialerSet,
			aliveTcp6DialerSet,
		},
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
	// TODO:
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
				return d.aliveDialerSets[0]
			case consts.IpVersionStr_6:
				return d.aliveDialerSets[1]
			}
		case consts.L4ProtoStr_UDP:
			switch typ.IpVersion {
			case consts.IpVersionStr_4:
				return d.aliveDialerSets[2]
			case consts.IpVersionStr_6:
				return d.aliveDialerSets[3]
			}
		}
	} else {
		switch typ.L4Proto {
		case consts.L4ProtoStr_TCP:
			switch typ.IpVersion {
			case consts.IpVersionStr_4:
				return d.aliveDialerSets[4]
			case consts.IpVersionStr_6:
				return d.aliveDialerSets[5]
			}
		case consts.L4ProtoStr_UDP:
		}
	}
	panic("invalid param")
}

// Select selects a dialer from group according to selectionPolicy.
func (g *DialerGroup) Select(networkType *dialer.NetworkType) (d *dialer.Dialer, latency time.Duration, err error) {
	if len(g.Dialers) == 0 {
		return nil, 0, fmt.Errorf("no dialer in this group")
	}

	a := g.MustGetAliveDialerSet(networkType)

	switch g.selectionPolicy.Policy {
	case consts.DialerSelectionPolicy_Random:
		d := a.GetRand()
		if d == nil {
			// No alive dialer.
			return nil, time.Hour, NoAliveDialerError
		}
		return d, 0, nil

	case consts.DialerSelectionPolicy_Fixed:
		if g.selectionPolicy.FixedIndex < 0 || g.selectionPolicy.FixedIndex >= len(g.Dialers) {
			return nil, 0, fmt.Errorf("selected dialer index is out of range")
		}
		return g.Dialers[g.selectionPolicy.FixedIndex], 0, nil

	case consts.DialerSelectionPolicy_MinLastLatency, consts.DialerSelectionPolicy_MinAverage10Latencies:
		d, latency := a.GetMinLatency()
		if d == nil {
			// No alive dialer.
			return nil, time.Hour, NoAliveDialerError
		}
		return d, latency, nil

	default:
		return nil, 0, fmt.Errorf("unsupported DialerSelectionPolicy: %v", g.selectionPolicy)
	}
}
