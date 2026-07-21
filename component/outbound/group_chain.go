/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
)

type groupChainDialer struct {
	entry          *DialerGroup
	spec           common.GroupChain
	option         *dialer.GlobalOption
	exits          map[*dialer.Dialer]netproxy.Dialer
	validationExit netproxy.Dialer
	mu             sync.Mutex
	current        [8]*dialer.Dialer
	preferCurrent  [8]bool
	retryAt        [8]map[*dialer.Dialer]time.Time
	closeOne       sync.Once
}

func NewGroupChainDialer(ctx context.Context, option *dialer.GlobalOption, entry *DialerGroup, spec common.GroupChain) (*dialer.Dialer, error) {
	chain, property, err := newGroupChainNetproxyDialer(option, entry, spec)
	if err != nil {
		return nil, err
	}
	return dialer.NewDialerContext(ctx, chain, option, dialer.InstanceOption{}, property), nil
}

func newGroupChainNetproxyDialer(option *dialer.GlobalOption, entry *DialerGroup, spec common.GroupChain) (*groupChainDialer, *dialer.Property, error) {
	if entry == nil {
		return nil, nil, fmt.Errorf("group chain %q references a nil entry group", spec.Name)
	}
	c := &groupChainDialer{
		entry:  entry,
		spec:   spec,
		option: option,
		exits:  make(map[*dialer.Dialer]netproxy.Dialer, len(entry.Dialers)),
	}
	var exitProperty *D.Property
	for _, entryDialer := range entry.Dialers {
		exit, property, err := D.NewNetproxyDialerFromLink(dialer.EnsureNetConn(entryDialer), &option.ExtraOption, spec.ExitLink)
		if err != nil {
			_ = c.Close()
			return nil, nil, fmt.Errorf("create group chain %q exit: %w", spec.Name, err)
		}
		c.exits[entryDialer] = exit
		if exitProperty == nil {
			exitProperty = property
		}
	}
	if exitProperty == nil {
		validationExit, property, err := D.NewNetproxyDialerFromLink(direct.SymmetricDirect, &option.ExtraOption, spec.ExitLink)
		if err != nil {
			return nil, nil, fmt.Errorf("create group chain %q exit: %w", spec.Name, err)
		}
		c.validationExit = validationExit
		exitProperty = property
	}
	name := spec.Name
	if name == "" {
		name = "group(" + spec.EntryGroup + ")->" + exitProperty.Name
	}
	property := &dialer.Property{
		Property: D.Property{
			Name:     name,
			Address:  exitProperty.Address,
			Protocol: "group(" + spec.EntryGroup + ")->" + exitProperty.Protocol,
			Link:     spec.Link,
		},
	}
	return c, property, nil
}

func (c *groupChainDialer) ReferencedGroupName() string { return c.spec.EntryGroup }

func (c *groupChainDialer) CloneWithGlobalOption(_ context.Context, option *dialer.GlobalOption) (netproxy.Dialer, error) {
	clone, _, err := newGroupChainNetproxyDialer(option, c.entry, c.spec)
	return clone, err
}

func (c *groupChainDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	nt := groupChainNetworkType(network, addr)
	candidates, err := c.candidates(nt)
	if err != nil {
		return nil, fmt.Errorf("entry node unavailable for group %q: %w", c.spec.EntryGroup, err)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("chain unavailable for new connections: all healthy entry nodes are awaiting retry")
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, netproxy.DialTimeout)
		defer cancel()
	}
	var errs []error
	for i, candidate := range candidates {
		exit := c.exits[candidate]
		if exit == nil {
			continue
		}
		attemptCtx := ctx
		cancelAttempt := func() {}
		if deadline, ok := ctx.Deadline(); ok && len(candidates)-i > 1 {
			remaining := time.Until(deadline)
			if remaining > 0 {
				attemptCtx, cancelAttempt = context.WithTimeout(ctx, remaining/time.Duration(len(candidates)-i))
			}
		}
		conn, err := exit.DialContext(attemptCtx, network, addr)
		cancelAttempt()
		if err == nil {
			c.setCurrent(nt, candidate)
			return conn, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", candidate.Property().Name, err))
		c.deferCandidate(nt, candidate)
		if c.entry.GetSelectionPolicy() == consts.DialerSelectionPolicy_Fixed {
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("chain unavailable for new connections: %w", errors.Join(errs...))
}

func (c *groupChainDialer) candidates(nt *dialer.NetworkType) ([]*dialer.Dialer, error) {
	selected, _, selectedType, err := c.entry.SelectWithExclusionResult(nt, true, nil)
	if err != nil {
		return nil, err
	}
	if selectedType == nil {
		selectedType = nt
	}
	if c.entry.GetSelectionPolicy() == consts.DialerSelectionPolicy_Fixed {
		if !selected.MustGetAlive(selectedType) {
			return nil, ErrNoAliveDialer
		}
		return []*dialer.Dialer{selected}, nil
	}
	idx := nt.Index()
	now := time.Now()
	c.mu.Lock()
	current := c.current[idx]
	preferCurrent := c.preferCurrent[idx]
	c.preferCurrent[idx] = false
	retryAt := make(map[*dialer.Dialer]time.Time, len(c.retryAt[idx]))
	for candidate, until := range c.retryAt[idx] {
		retryAt[candidate] = until
	}
	c.mu.Unlock()
	result := make([]*dialer.Dialer, 0, len(c.entry.Dialers))
	appendCandidate := func(candidate *dialer.Dialer) {
		if candidate == nil {
			return
		}
		if !candidate.MustGetAlive(selectedType) {
			return
		}
		for _, existing := range result {
			if existing == candidate {
				return
			}
		}
		if until := retryAt[candidate]; until.After(now) {
			return
		}
		result = append(result, candidate)
	}
	if preferCurrent {
		appendCandidate(current)
	}
	appendCandidate(selected)
	appendCandidate(current)
	healthyCount := 0
	for _, candidate := range c.entry.Dialers {
		if candidate.MustGetAlive(selectedType) {
			healthyCount++
			appendCandidate(candidate)
		}
	}
	if healthyCount == 0 {
		return nil, ErrNoAliveDialer
	}
	return result, nil
}

func (c *groupChainDialer) setCurrent(nt *dialer.NetworkType, candidate *dialer.Dialer) {
	c.mu.Lock()
	c.current[nt.Index()] = candidate
	if c.retryAt[nt.Index()] != nil {
		delete(c.retryAt[nt.Index()], candidate)
	}
	c.mu.Unlock()
}

func (c *groupChainDialer) deferCandidate(nt *dialer.NetworkType, candidate *dialer.Dialer) {
	idx := nt.Index()
	interval := time.Duration(0)
	if c.option != nil {
		interval = c.option.CheckInterval
	}
	if interval <= 0 {
		interval = c.entry.MinCheckInterval()
	}
	c.mu.Lock()
	if c.retryAt[idx] == nil {
		c.retryAt[idx] = make(map[*dialer.Dialer]time.Time)
	}
	c.retryAt[idx][candidate] = time.Now().Add(interval)
	c.mu.Unlock()
}

func groupChainNetworkType(network, addr string) *dialer.NetworkType {
	magic, err := netproxy.ParseMagicNetwork(network)
	if err == nil {
		network = magic.Network
	}
	l4 := consts.L4ProtoStr_TCP
	if strings.HasPrefix(network, "udp") {
		l4 = consts.L4ProtoStr_UDP
	}
	ipVersion := consts.IpVersionStr("")
	if magic != nil && magic.IPVersion != "" {
		ipVersion = consts.IpVersionStr(magic.IPVersion)
	}
	if ipVersion == "" {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
				ipVersion = consts.IpVersionFromAddr(ip)
			}
		}
	}
	if ipVersion == "" {
		if strings.HasSuffix(network, "6") {
			ipVersion = consts.IpVersionStr_6
		} else {
			ipVersion = consts.IpVersionStr_4
		}
	}
	nt := &dialer.NetworkType{L4Proto: l4, IpVersion: ipVersion}
	if l4 == consts.L4ProtoStr_UDP {
		nt.IsDns = true
		nt.UdpHealthDomain = dialer.UdpHealthDomainDns
	}
	return nt
}

func (c *groupChainDialer) Close() error {
	var closeErr error
	c.closeOne.Do(func() {
		for _, exit := range c.exits {
			if closer, ok := exit.(interface{ Close() error }); ok {
				closeErr = errors.Join(closeErr, closer.Close())
			}
		}
		if closer, ok := c.validationExit.(interface{ Close() error }); ok {
			closeErr = errors.Join(closeErr, closer.Close())
		}
	})
	return closeErr
}

func RestoreGroupChainSelection(current, previous netproxy.Dialer) {
	to, ok := current.(*groupChainDialer)
	if !ok {
		return
	}
	from, ok := previous.(*groupChainDialer)
	if !ok || to.spec.EntryGroup != from.spec.EntryGroup || to.spec.ExitLink != from.spec.ExitLink ||
		to.entry == nil || from.entry == nil ||
		to.entry.currentSelectionState().policy != from.entry.currentSelectionState().policy {
		return
	}
	from.mu.Lock()
	var names [8]string
	for idx, old := range from.current {
		if old != nil && old.Property() != nil {
			names[idx] = old.Property().Name
		}
	}
	from.mu.Unlock()
	to.mu.Lock()
	defer to.mu.Unlock()
	for idx, name := range names {
		if name == "" {
			continue
		}
		for candidate := range to.exits {
			if candidate.Property() != nil && candidate.Property().Name == name {
				to.current[idx] = candidate
				to.preferCurrent[idx] = true
				break
			}
		}
	}
}
