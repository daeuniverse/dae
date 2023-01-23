/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package outbound

import (
	"fmt"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
	"net"
)

type DialerSelectionPolicy struct {
	Policy     consts.DialerSelectionPolicy
	FixedIndex int
}

type DialerGroup struct {
	proxy.Dialer

	log  *logrus.Logger
	Name string

	Dialers []*dialer.Dialer

	registeredAliveDialerSet bool
	AliveDialerSet           *dialer.AliveDialerSet

	selectionPolicy *DialerSelectionPolicy
}

func NewDialerGroup(log *logrus.Logger, name string, dialers []*dialer.Dialer, p DialerSelectionPolicy) *DialerGroup {
	var registeredAliveDialerSet bool
	a := dialer.NewAliveDialerSet(log, p.Policy, dialers, true)

	switch p.Policy {
	case consts.DialerSelectionPolicy_Random,
		consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies:
		// Need to know the alive state or latency.
		for _, d := range dialers {
			d.RegisterAliveDialerSet(a)
		}
		registeredAliveDialerSet = true

	case consts.DialerSelectionPolicy_Fixed:
		// No need to know if the dialer is alive.

	default:
		log.Panicf("Unexpected dialer selection policy: %v", p.Policy)
	}

	return &DialerGroup{
		log:                      log,
		Name:                     name,
		Dialers:                  dialers,
		AliveDialerSet:           a,
		registeredAliveDialerSet: registeredAliveDialerSet,
		selectionPolicy:          &p,
	}
}

func (g *DialerGroup) Close() error {
	if g.registeredAliveDialerSet {
		for _, d := range g.Dialers {
			d.UnregisterAliveDialerSet(g.AliveDialerSet)
		}
	}
	return nil
}

func (g *DialerGroup) SetSelectionPolicy(policy DialerSelectionPolicy) {
	// TODO:
	g.selectionPolicy = &policy
}

// Select selects a dialer from group according to selectionPolicy.
func (g *DialerGroup) Select() (*dialer.Dialer, error) {
	if len(g.Dialers) == 0 {
		return nil, fmt.Errorf("no dialer in this group")
	}

	switch g.selectionPolicy.Policy {
	case consts.DialerSelectionPolicy_Random:
		d := g.AliveDialerSet.GetRand()
		if d == nil {
			// No alive dialer.
			// TODO: Should we throw an error to block the connection in this condition?
			g.log.Warnf("No alive dialer in DialerGroup %v, use DIRECT. It may cause IP leaking.", g.Name)
			return dialer.FullconeDirectDialer, nil
		}
		return d, nil

	case consts.DialerSelectionPolicy_Fixed:
		if g.selectionPolicy.FixedIndex < 0 || g.selectionPolicy.FixedIndex >= len(g.Dialers) {
			return nil, fmt.Errorf("selected dialer index is out of range")
		}
		return g.Dialers[g.selectionPolicy.FixedIndex], nil

	case consts.DialerSelectionPolicy_MinLastLatency, consts.DialerSelectionPolicy_MinAverage10Latencies:
		d := g.AliveDialerSet.GetMinLatency()
		if d == nil {
			// No alive dialer.
			// TODO: Should we throw an error to block the connection in this condition?
			g.log.Warnf("No alive dialer in DialerGroup %v, use DIRECT. It may cause IP leaking.", g.Name)
			return dialer.FullconeDirectDialer, nil
		}
		return d, nil

	default:
		return nil, fmt.Errorf("unsupported DialerSelectionPolicy: %v", g.selectionPolicy)
	}
}

func (g *DialerGroup) Dial(network string, addr string) (c net.Conn, err error) {
	d, err := g.Select()
	if err != nil {
		return nil, err
	}
	return d.Dial(network, addr)
}
