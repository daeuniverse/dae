/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package outbound

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/component/outbound/dialer"
	"github.com/v2rayA/dae/config"
	"github.com/v2rayA/dae/pkg/config_parser"
	"golang.org/x/net/proxy"
	"net"
	"strconv"
)

type DialerSelectionPolicy struct {
	Policy     consts.DialerSelectionPolicy
	FixedIndex int
}

func NewDialerSelectionPolicyFromGroupParam(param *config.GroupParam) (policy *DialerSelectionPolicy, err error) {
	switch val := param.Policy.(type) {
	case string:
		switch consts.DialerSelectionPolicy(val) {
		case consts.DialerSelectionPolicy_Random,
			consts.DialerSelectionPolicy_MinAverage10Latencies,
			consts.DialerSelectionPolicy_MinLastLatency:
			return &DialerSelectionPolicy{
				Policy: consts.DialerSelectionPolicy(val),
			}, nil
		case consts.DialerSelectionPolicy_Fixed:
			return nil, fmt.Errorf("%v need to specify node index", val)
		default:
			return nil, fmt.Errorf("unexpected policy: %v", val)
		}
	case []*config_parser.Function:
		if len(val) > 1 || len(val) == 0 {
			logrus.Debugf("%@", val)
			return nil, fmt.Errorf("policy should be exact 1 function: got %v", len(val))
		}
		f := val[0]
		switch consts.DialerSelectionPolicy(f.Name) {
		case consts.DialerSelectionPolicy_Fixed:
			// Should be like:
			// policy: fixed(0)
			if len(f.Params) > 1 || f.Params[0].Key != "" {
				return nil, fmt.Errorf(`invalid "%v" param format`, f.Name)
			}
			strIndex := f.Params[0].Val
			index, err := strconv.Atoi(strIndex)
			if len(f.Params) > 1 || f.Params[0].Key != "" {
				return nil, fmt.Errorf(`invalid "%v" param format: %w`, f.Name, err)
			}
			return &DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy(f.Name),
				FixedIndex: index,
			}, nil
		default:
			return nil, fmt.Errorf("unexpected policy func: %v", f.Name)
		}
	default:
		return nil, fmt.Errorf("unexpected param.Policy.(type): %T", val)
	}
}

type DialerGroup struct {
	proxy.Dialer
	block *dialer.Dialer

	log  *logrus.Logger
	Name string

	Dialers []*dialer.Dialer

	registeredAliveDialerSet bool
	AliveDialerSet           *dialer.AliveDialerSet

	selectionPolicy *DialerSelectionPolicy
}

func NewDialerGroup(option *dialer.GlobalOption, name string, dialers []*dialer.Dialer, p DialerSelectionPolicy) *DialerGroup {
	log := option.Log
	var registeredAliveDialerSet bool
	a := dialer.NewAliveDialerSet(log, name, p.Policy, dialers, true)

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
		block:                    dialer.NewBlockDialer(option),
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
			g.log.Warnf("No alive dialer in DialerGroup %v, use \"block\".", g.Name)
			return g.block, nil
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
			g.log.Warnf("No alive dialer in DialerGroup %v, use \"block\".", g.Name)
			return g.block, nil
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
	g.log.Tracef("Group [%v] dial using <%v>", g.Name, d.Name())
	return d.Dial(network, addr)
}
