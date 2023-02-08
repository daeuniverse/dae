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
	"golang.org/x/net/proxy"
	"net"
	"net/netip"
	"strings"
)

type DialerGroup struct {
	proxy.Dialer
	block *dialer.Dialer

	log  *logrus.Logger
	Name string

	Dialers []*dialer.Dialer

	registeredAliveDialerSet bool
	AliveTcp4DialerSet       *dialer.AliveDialerSet
	AliveTcp6DialerSet       *dialer.AliveDialerSet
	AliveUdp4DialerSet       *dialer.AliveDialerSet
	AliveUdp6DialerSet       *dialer.AliveDialerSet

	selectionPolicy *DialerSelectionPolicy
}

func NewDialerGroup(option *dialer.GlobalOption, name string, dialers []*dialer.Dialer, p DialerSelectionPolicy) *DialerGroup {
	log := option.Log
	var registeredAliveDialerSet bool
	aliveTcp4DialerSet := dialer.NewAliveDialerSet(log, name, consts.L4ProtoStr_TCP, consts.IpVersionStr_4, p.Policy, dialers, true)
	aliveTcp6DialerSet := dialer.NewAliveDialerSet(log, name, consts.L4ProtoStr_TCP, consts.IpVersionStr_6, p.Policy, dialers, true)
	aliveUdp4DialerSet := dialer.NewAliveDialerSet(log, name, consts.L4ProtoStr_UDP, consts.IpVersionStr_4, p.Policy, dialers, true)
	aliveUdp6DialerSet := dialer.NewAliveDialerSet(log, name, consts.L4ProtoStr_UDP, consts.IpVersionStr_6, p.Policy, dialers, true)

	switch p.Policy {
	case consts.DialerSelectionPolicy_Random,
		consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies:
		// Need to know the alive state or latency.
		for _, d := range dialers {
			d.RegisterAliveDialerSet(aliveTcp4DialerSet, consts.L4ProtoStr_TCP, consts.IpVersionStr_4)
			d.RegisterAliveDialerSet(aliveTcp6DialerSet, consts.L4ProtoStr_TCP, consts.IpVersionStr_6)
			d.RegisterAliveDialerSet(aliveUdp4DialerSet, consts.L4ProtoStr_UDP, consts.IpVersionStr_4)
			d.RegisterAliveDialerSet(aliveUdp6DialerSet, consts.L4ProtoStr_UDP, consts.IpVersionStr_6)
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
		AliveTcp4DialerSet:       aliveTcp4DialerSet,
		AliveTcp6DialerSet:       aliveTcp6DialerSet,
		AliveUdp4DialerSet:       aliveUdp4DialerSet,
		AliveUdp6DialerSet:       aliveUdp6DialerSet,
		registeredAliveDialerSet: registeredAliveDialerSet,
		selectionPolicy:          &p,
	}
}

func (g *DialerGroup) Close() error {
	if g.registeredAliveDialerSet {
		for _, d := range g.Dialers {
			d.UnregisterAliveDialerSet(g.AliveTcp4DialerSet, consts.L4ProtoStr_TCP, consts.IpVersionStr_4)
			d.UnregisterAliveDialerSet(g.AliveTcp6DialerSet, consts.L4ProtoStr_TCP, consts.IpVersionStr_6)
			d.UnregisterAliveDialerSet(g.AliveUdp4DialerSet, consts.L4ProtoStr_UDP, consts.IpVersionStr_4)
			d.UnregisterAliveDialerSet(g.AliveUdp6DialerSet, consts.L4ProtoStr_UDP, consts.IpVersionStr_6)
		}
	}
	return nil
}

func (g *DialerGroup) SetSelectionPolicy(policy DialerSelectionPolicy) {
	// TODO:
	g.selectionPolicy = &policy
}

// Select selects a dialer from group according to selectionPolicy.
func (g *DialerGroup) Select(l4proto consts.L4ProtoStr, ipversion consts.IpVersionStr) (*dialer.Dialer, error) {
	if len(g.Dialers) == 0 {
		return nil, fmt.Errorf("no dialer in this group")
	}
	var a *dialer.AliveDialerSet
	switch l4proto {
	case consts.L4ProtoStr_TCP:
		switch ipversion {
		case consts.IpVersionStr_4:
			a = g.AliveTcp4DialerSet
		case consts.IpVersionStr_6:
			a = g.AliveTcp6DialerSet
		}
	case consts.L4ProtoStr_UDP:
		switch ipversion {
		case consts.IpVersionStr_4:
			a = g.AliveUdp4DialerSet
		case consts.IpVersionStr_6:
			a = g.AliveUdp6DialerSet
		}
	default:
		return nil, fmt.Errorf("DialerGroup.Select: unexpected l4proto type: %v", l4proto)
	}

	switch g.selectionPolicy.Policy {
	case consts.DialerSelectionPolicy_Random:
		d := a.GetRand()
		if d == nil {
			// No alive dialer.
			g.log.WithFields(logrus.Fields{
				"l4proto": l4proto,
				"group":   g.Name,
			}).Warnf("No alive dialer in DialerGroup, use \"block\".")
			return g.block, nil
		}
		return d, nil

	case consts.DialerSelectionPolicy_Fixed:
		if g.selectionPolicy.FixedIndex < 0 || g.selectionPolicy.FixedIndex >= len(g.Dialers) {
			return nil, fmt.Errorf("selected dialer index is out of range")
		}
		return g.Dialers[g.selectionPolicy.FixedIndex], nil

	case consts.DialerSelectionPolicy_MinLastLatency, consts.DialerSelectionPolicy_MinAverage10Latencies:
		d := a.GetMinLatency()
		if d == nil {
			// No alive dialer.
			g.log.WithFields(logrus.Fields{
				"l4proto": l4proto,
				"group":   g.Name,
			}).Warnf("No alive dialer in DialerGroup, use \"block\".")
			return g.block, nil
		}
		return d, nil

	default:
		return nil, fmt.Errorf("unsupported DialerSelectionPolicy: %v", g.selectionPolicy)
	}
}

func (g *DialerGroup) Dial(network string, addr string) (c net.Conn, err error) {
	var d proxy.Dialer
	ipAddr, err := netip.ParseAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("DialerGroup.Dial only supports ip as addr")
	}
	ipversion := consts.IpVersionFromAddr(ipAddr)
	switch {
	case strings.HasPrefix(network, "tcp"):
		d, err = g.Select(consts.L4ProtoStr_TCP, ipversion)
	case strings.HasPrefix(network, "udp"):
		d, err = g.Select(consts.L4ProtoStr_UDP, ipversion)
	default:
		return nil, fmt.Errorf("unexpected network: %v", network)
	}
	if err != nil {
		return nil, err
	}
	return d.Dial(network, addr)
}
