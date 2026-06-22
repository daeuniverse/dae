/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
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

	selectionState   atomic.Pointer[dialerGroupSelectionState]
	selectionStateMu sync.Mutex

	dialersAnnotations  []*dialer.Annotation
	checkTolerance      time.Duration
	aliveChangeCallback func(alive bool, networkType *dialer.NetworkType, isInit bool)

	resuscitateLastTime atomic.Int64
	noAliveLogLastTimes [8]atomic.Int64

	// fixed_fallback retry state (protected by fixedFallbackMu)
	fixedFallbackMu            sync.Mutex
	fixedFallbackDeadSince     int64
	fixedFallbackRetryCount    int64
	fixedFallbackLastRetryNano int64
	// Background retry goroutine for fixed_fallback.
	// Started when the fixed node is first detected dead.
	// Stopped when the node recovers (MustGetAlive=true).
	fixedFallbackStopCh  chan struct{}
	fixedFallbackRunning atomic.Bool

	// fixed_fallback log rate limit
	fixedFallbackLastLogMark atomic.Int64
	fixedFallbackLastLogTime atomic.Int64

	cachedMinCheckInterval time.Duration
}

type dialerGroupSelectionState struct {
	policy          DialerSelectionPolicy
	aliveDialerSets [8]*dialer.AliveDialerSet
}

// ReloadSelectionFallback records the candidate selected by a fresh group
// before reload health inheritance applies the previous generation's state.
type ReloadSelectionFallback [8]*dialer.Dialer

func NewDialerGroup(
	option *dialer.GlobalOption,
	name string,
	dialers []*dialer.Dialer,
	dialersAnnotations []*dialer.Annotation,
	p DialerSelectionPolicy,
	aliveChangeCallback func(alive bool, networkType *dialer.NetworkType, isInit bool),
) *DialerGroup {
	log := option.Log

	group := &DialerGroup{
		log:                 log,
		Name:                name,
		Dialers:             dialers,
		dialersAnnotations:  dialersAnnotations,
		checkTolerance:      option.CheckTolerance,
		aliveChangeCallback: aliveChangeCallback,
	}
	state := group.buildSelectionState(p, true)
	group.registerAliveDialerSets(state.aliveDialerSets)
	group.selectionState.Store(state)
	group.cachedMinCheckInterval = group.MinCheckInterval()

	// Register a callback on the fixed dialer so the background retry
	// goroutine starts when the health check marks the node as dead,
	// not only when traffic flows through Select().
	if p.Policy == consts.DialerSelectionPolicy_FixedWithFallback &&
		p.FixedIndex >= 0 && p.FixedIndex < len(dialers) {
		fixed := dialers[p.FixedIndex]
		if fixed != nil {
			fixed.RegisterAliveTransitionCallback(func(nt *dialer.NetworkType, alive bool) {
				if alive {
					return
				}
				if group.fixedFallbackRunning.CompareAndSwap(false, true) {
					group.fixedFallbackStopCh = make(chan struct{})
					group.fixedFallbackMu.Lock()
					group.fixedFallbackDeadSince = time.Now().UnixNano()
					group.fixedFallbackRetryCount = 0
					group.fixedFallbackMu.Unlock()
					go group.runFixedFallbackRetry(fixed, p, nt)
				}
			})
		}
	}

	for _, nt := range standardSelectionNetworkTypes() {
		aliveChangeCallback(true, nt, true)
	}

	return group
}

func (g *DialerGroup) Close() error {
	g.unregisterAliveDialerSets(g.currentSelectionState().aliveDialerSets)
	return nil
}

func (g *DialerGroup) SetSelectionPolicy(policy DialerSelectionPolicy) {
	g.selectionStateMu.Lock()
	defer g.selectionStateMu.Unlock()

	current := g.currentSelectionState()
	currentNeedsAliveState := policyNeedsAliveState(current.policy.Policy)
	newNeedsAliveState := policyNeedsAliveState(policy.Policy)

	switch {
	case currentNeedsAliveState && newNeedsAliveState:
		if current.policy.Policy != policy.Policy {
			for _, set := range uniqueAliveDialerSets(current.aliveDialerSets) {
				set.SetSelectionPolicy(policy.Policy)
			}
		}
		next := &dialerGroupSelectionState{
			policy:          policy,
			aliveDialerSets: current.aliveDialerSets,
		}
		g.selectionState.Store(next)

	case !currentNeedsAliveState && !newNeedsAliveState:
		g.selectionState.Store(&dialerGroupSelectionState{policy: policy})

	case !currentNeedsAliveState && newNeedsAliveState:
		next := g.buildSelectionState(policy, true)
		g.registerAliveDialerSets(next.aliveDialerSets)
		for _, d := range g.Dialers {
			d.ActivateCheck()
		}
		g.selectionState.Store(next)

	case currentNeedsAliveState && !newNeedsAliveState:
		oldSets := current.aliveDialerSets
		g.selectionState.Store(&dialerGroupSelectionState{policy: policy})
		g.unregisterAliveDialerSets(oldSets)
	}
}

func (g *DialerGroup) GetSelectionPolicy() (policy consts.DialerSelectionPolicy) {
	return g.currentSelectionState().policy.Policy
}

func (g *DialerGroup) MinCheckInterval() time.Duration {
	if len(g.Dialers) == 0 {
		return 30 * time.Second
	}
	min := g.Dialers[0].CheckInterval
	for _, d := range g.Dialers[1:] {
		if d.CheckInterval < min {
			min = d.CheckInterval
		}
	}
	if min < 2*time.Second {
		return 2 * time.Second
	}
	return min
}

func (d *DialerGroup) MustGetAliveDialerSet(typ *dialer.NetworkType) *dialer.AliveDialerSet {
	return d.currentSelectionState().aliveDialerSets[typ.Index()]
}

// CaptureReloadSelectionFallback captures one fallback candidate per network
// type so reload inheritance can avoid leaving a group with no selectable dialer.
func (g *DialerGroup) CaptureReloadSelectionFallback() ReloadSelectionFallback {
	var fallback ReloadSelectionFallback
	if g == nil {
		return fallback
	}
	for _, nt := range standardSelectionNetworkTypes() {
		d, _, _, err := g.SelectWithExclusionResult(nt, false, nil)
		if err == nil && d != nil {
			fallback[nt.Index()] = d
		}
	}
	return fallback
}

// EnsureReloadSelectionFloor keeps exactly one fallback candidate alive for
// network types whose inherited health state would otherwise be empty.
func (g *DialerGroup) EnsureReloadSelectionFloor(fallback ReloadSelectionFallback) {
	if g == nil {
		return
	}
	for _, nt := range standardSelectionNetworkTypes() {
		set := g.MustGetAliveDialerSet(nt)
		if set == nil || set.Len() > 0 {
			continue
		}
		candidate := fallback[nt.Index()]
		if candidate == nil && len(g.Dialers) > 0 {
			candidate = g.Dialers[0]
		}
		if candidate == nil {
			continue
		}
		candidate.MarkAliveForReloadFallback(nt)
		if g.log != nil && g.log.IsLevelEnabled(logrus.DebugLevel) {
			dialerName := ""
			if p := candidate.Property(); p != nil {
				dialerName = p.Name
			}
			g.log.WithFields(logrus.Fields{
				"dialer":  dialerName,
				"group":   g.Name,
				"network": nt.String(),
			}).Debugln("Reload health inheritance kept a selection fallback alive")
		}
	}
}

// tryDoRateLimitedAction checks if an action can be performed based on a rate limit.
// It uses atomic operations to ensure thread-safety with minimal overhead.
func (g *DialerGroup) tryDoRateLimitedAction(last *atomic.Int64, interval time.Duration) bool {
	now := time.Now().UnixNano()
	l := last.Load()
	if now-l < int64(interval) {
		return false
	}
	return last.CompareAndSwap(l, now)
}

// HandleNoAliveDialer is the unified entry point for handling dialer selection failures.
// IT MUST ONLY BE CALLED ON THE ERROR PATH to ensure zero overhead for successful requests.
// It automatically triggers a resuscitation probe and logs the failure, both subject to
// their respective (cached) rate limits.
func (g *DialerGroup) HandleNoAliveDialer(
	origNetworkType string,
	selectionNetworkType *dialer.NetworkType,
	src netip.AddrPort,
	dst netip.AddrPort,
	domain string,
	strictIpVersion bool,
) {
	// 1. Attempt resuscitation (rate-limited by min check interval)
	if g.tryDoRateLimitedAction(&g.resuscitateLastTime, g.cachedMinCheckInterval) {
		g.resuscitate(selectionNetworkType)
	}

	// 2. Log the failure (rate-limited by 5x check interval, min 10s)
	idx := selectionNetworkType.Index()
	logInterval := max(g.cachedMinCheckInterval*5, 10*time.Second)

	if g.tryDoRateLimitedAction(&g.noAliveLogLastTimes[idx], logInterval) {
		g.logNoAlive(origNetworkType, selectionNetworkType, src, dst, domain, strictIpVersion, logInterval)
	}
}

// Resuscitate triggers a targeted health check for all dialers in the group.
// It is rate-limited to once per group per MinCheckInterval to prevent worker pool starvation.
// Returns true if a resuscitation probe was actually signaled.
func (g *DialerGroup) Resuscitate(networkType *dialer.NetworkType) bool {
	if g.tryDoRateLimitedAction(&g.resuscitateLastTime, g.cachedMinCheckInterval) {
		g.resuscitate(networkType)
		return true
	}
	return false
}

func (g *DialerGroup) resuscitate(networkType *dialer.NetworkType) {
	for _, d := range g.Dialers {
		if networkType.L4Proto == consts.L4ProtoStr_UDP {
			// UDP admission may recover through DNS-UDP first and then shared TCP.
			// Probe both families so emergency recovery does not wait for the next
			// periodic full check when only the TCP fallback has come back.
			d.NotifyCheckDnsUdp()
			d.NotifyCheckTcp()
			continue
		}
		d.NotifyCheckTcp()
	}
}

// LogNoAliveDialer logs a warning when no alive dialer is found for selection.
// It is rate-limited per network type to prevent log spam.
func (g *DialerGroup) LogNoAliveDialer(
	origNetworkType string,
	selectionNetworkType *dialer.NetworkType,
	src netip.AddrPort,
	dst netip.AddrPort,
	domain string,
	strictIpVersion bool,
) {
	idx := selectionNetworkType.Index()
	interval := max(g.cachedMinCheckInterval*5, 10*time.Second)

	if g.tryDoRateLimitedAction(&g.noAliveLogLastTimes[idx], interval) {
		g.logNoAlive(origNetworkType, selectionNetworkType, src, dst, domain, strictIpVersion, interval)
	}
}

func (g *DialerGroup) logNoAlive(
	origNetworkType string,
	selectionNetworkType *dialer.NetworkType,
	src netip.AddrPort,
	dst netip.AddrPort,
	domain string,
	strictIpVersion bool,
	interval time.Duration,
) {
	total := len(g.Dialers)
	alive := 0
	if a := g.MustGetAliveDialerSet(selectionNetworkType); a != nil {
		alive = a.Len()
	}

	g.log.WithFields(logrus.Fields{
		"outbound":               g.Name,
		"orig_network_type":      origNetworkType,
		"selection_network_type": selectionNetworkType.String(),
		"src":                    src.String(),
		"to":                     dst.String(),
		"sniffed":                domain,
		"interval":               interval.String(),
		"total":                  total,
		"alive":                  alive,
	}).Warn("no alive dialer for selection (rate-limited)")
}

// logFixedFallback records state transitions for the fixed_fallback policy.
// Mark values: 0=alive/recovery, 1=dead_detected, >=10=retry step,
// -1=fallen back to alternative.
func (g *DialerGroup) logFixedFallback(state int64, fixed *dialer.Dialer, nt *dialer.NetworkType) {
	if g.log == nil {
		return
	}
	nodeName := ""
	if fixed != nil && fixed.Property() != nil {
		nodeName = fixed.Property().Name
	}

	switch {
	case state == 0:
		// Recovery: fixed dialer is alive again
		old := g.fixedFallbackLastLogMark.Swap(0)
		if old != 0 {
			g.log.WithFields(logrus.Fields{
				"group":   g.Name,
				"dialer":  nodeName,
				"network": nt.String(),
			}).Infoln("Fixed dialer is ALIVE, traffic restored")
		}
	case state == 1:
		// First time detecting dead: log and update state
		old := g.fixedFallbackLastLogMark.Swap(1)
		if old != 1 {
			g.log.WithFields(logrus.Fields{
				"group":   g.Name,
				"dialer":  nodeName,
				"network": nt.String(),
			}).Warnln("Fixed dialer DEAD, starting retry")
		}
	case state >= 10:
		// Retry: log the actual retry count (state - 10)
		retryCount := state - 10
		old := g.fixedFallbackLastLogMark.Swap(state)
		if old != state {
			g.log.WithFields(logrus.Fields{
				"group":   g.Name,
				"dialer":  nodeName,
				"network": nt.String(),
			}).Infoln("Fixed dialer retry", retryCount)
		}
	case state < 0:
		// Fallen back to alternative
		old := g.fixedFallbackLastLogMark.Swap(-1)
		if old >= 0 {
			g.log.WithFields(logrus.Fields{
				"group":   g.Name,
				"dialer":  nodeName,
				"network": nt.String(),
			}).Warnln("Fixed dialer DEAD, fallen back to alternative")
		}
	}
}

// Select is a backward-compatible wrapper for SelectWithExclusion.
func (g *DialerGroup) Select(networkType *dialer.NetworkType, strictIpVersion bool) (d *dialer.Dialer, latency time.Duration, err error) {
	d, latency, _, err = g.SelectWithExclusionResult(networkType, strictIpVersion, nil)
	return d, latency, err
}

// SelectWithExclusion selects a dialer from group according to selectionPolicy.
// The 'excluded' parameter specifies a dialer to avoid during selection (for
// failover scenarios). Note that Fixed policy ignores 'excluded' because user
// configuration takes precedence over automatic exclusion.
// If 'strictIpVersion' is false and no alive dialer, it will fallback to another ipversion.
func (g *DialerGroup) SelectWithExclusion(networkType *dialer.NetworkType, strictIpVersion bool, excluded *dialer.Dialer) (d *dialer.Dialer, latency time.Duration, err error) {
	d, latency, _, err = g.SelectWithExclusionResult(networkType, strictIpVersion, excluded)
	return d, latency, err
}

// SelectWithExclusionResult returns the chosen dialer together with the health
// domain actually used to admit that dialer. For ordinary selections this is
// the requested network type; for data-UDP recovery it may be DNS-UDP or TCP.
func (g *DialerGroup) SelectWithExclusionResult(networkType *dialer.NetworkType, strictIpVersion bool, excluded *dialer.Dialer) (d *dialer.Dialer, latency time.Duration, selectedNetworkType *dialer.NetworkType, err error) {
	state := g.currentSelectionState()
	policy := state.policy
	d, latency, selectedNetworkType, err = g._select(networkType, state, policy, excluded)
	if !strictIpVersion && errors.Is(err, ErrNoAliveDialer) {
		// Fallback to another ipversion. Use local copy to avoid modifying the original networkType if it's passed by reference.
		nt := *networkType
		nt.IpVersion = (consts.IpVersion_X - networkType.IpVersion.ToIpVersionType()).ToIpVersionStr()
		return g._select(&nt, state, policy, excluded)
	}
	if err == nil {
		return d, latency, selectedNetworkType, nil
	}
	if errors.Is(err, ErrNoAliveDialer) && len(g.Dialers) == 1 {
		// There is only one dialer in this group. Just choose it instead of return error.
		if d, _, selectedNetworkType, err = g._select(networkType, state, DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 0,
		}, excluded); err != nil {
			return nil, 0, nil, err
		}
		return d, dialer.Timeout, selectedNetworkType, nil
	}
	return nil, latency, selectedNetworkType, err
}

func (g *DialerGroup) _select(networkType *dialer.NetworkType, state *dialerGroupSelectionState, policy DialerSelectionPolicy, excluded *dialer.Dialer) (d *dialer.Dialer, latency time.Duration, selectedNetworkType *dialer.NetworkType, err error) {
	if len(g.Dialers) == 0 {
		return nil, 0, nil, fmt.Errorf("no dialer in this group")
	}
	switch policy.Policy {
	case consts.DialerSelectionPolicy_Random:
		networkTypes, count := g.selectionNetworkTypes(networkType, policy)
		for i := range count {
			a := state.aliveDialerSets[networkTypes[i].Index()]
			d := a.GetRandExcluded(excluded)
			if d != nil {
				selected := preferAlternateSelectionNetworkType(d, &networkTypes[i])
				return d, 0, selected, nil
			}
		}
		return nil, time.Hour, nil, ErrNoAliveDialer

	case consts.DialerSelectionPolicy_Fixed:
		// Fixed policy represents explicit user intent to use a specific dialer.
		// It ignores the 'excluded' parameter because user configuration takes
		// precedence over automatic exclusion. Even if the dialer is marked as
		// excluded, Fixed policy returns it as configured.
		if policy.FixedIndex < 0 || policy.FixedIndex >= len(g.Dialers) {
			return nil, 0, nil, fmt.Errorf("selected dialer index is out of range")
		}
		selected := preferAlternateSelectionNetworkType(g.Dialers[policy.FixedIndex], networkType)
		return g.Dialers[policy.FixedIndex], 0, selected, nil

	case consts.DialerSelectionPolicy_FixedWithFallback:
		if policy.FixedIndex < 0 || policy.FixedIndex >= len(g.Dialers) {
			return nil, 0, nil, fmt.Errorf("selected dialer index is out of range")
		}
		fixed := g.Dialers[policy.FixedIndex]

		fallbackPolicy := DialerSelectionPolicy{Policy: policy.FallbackPolicy}
		networkTypes, count := g.selectionNetworkTypes(networkType, fallbackPolicy)

		for i := range count {
			a := state.aliveDialerSets[networkTypes[i].Index()]
			if a == nil {
				continue
			}
			nt := &networkTypes[i]

			// Try fixed dialer first
			if fixed != nil && fixed.MustGetAlive(nt) {
				// Node is alive → reset retry state and use it
				g.fixedFallbackMu.Lock()
				wasDead := g.fixedFallbackDeadSince != 0
				g.fixedFallbackDeadSince = 0
				g.fixedFallbackRetryCount = 0
				g.fixedFallbackMu.Unlock()
				if wasDead {
					g.logFixedFallback(0, fixed, nt)
				}
				selected := preferAlternateSelectionNetworkType(fixed, nt)
				return fixed, 0, selected, nil
			}

			// Fixed dialer is dead → fallback.
			// Retries are handled by the background goroutine.
			var (
				nowNano       int64
				deadSinceNano int64
			)

			g.fixedFallbackMu.Lock()
			nowNano = time.Now().UnixNano()
			deadSinceNano = g.fixedFallbackDeadSince

			if deadSinceNano == 0 {
				// First Select() finding this node dead.
				// Start background retry goroutine if not already running
				// (may have been started by aliveTransitionCallback already).
				g.fixedFallbackDeadSince = nowNano
				g.fixedFallbackRetryCount = 0
				g.fixedFallbackMu.Unlock()
				g.logFixedFallback(1, fixed, nt)

				if g.fixedFallbackRunning.CompareAndSwap(false, true) {
					g.fixedFallbackStopCh = make(chan struct{})
					go g.runFixedFallbackRetry(fixed, policy, nt)
				}

				// Background goroutine handles retries separately.
				// Natural traffic falls back immediately.
				goto doFallback
			}

			// Node already known dead. Background goroutine owns retries.
			// Fallback immediately — no retryCount/elapsed check.
			g.fixedFallbackMu.Unlock()
			g.logFixedFallback(-1, fixed, nt)
			goto doFallback

		doFallback:
			switch policy.FallbackPolicy {
			case consts.DialerSelectionPolicy_Random:
				d := a.GetRandExcluded(excluded)
				if d != nil {
					selected := preferAlternateSelectionNetworkType(d, nt)
					return d, 0, selected, nil
				}
			case consts.DialerSelectionPolicy_MinLastLatency,
				consts.DialerSelectionPolicy_MinAverage10Latencies,
				consts.DialerSelectionPolicy_MinMovingAverageLatencies:
				d, lat := a.GetMinLatency(excluded)
				if d != nil {
					selected := preferAlternateSelectionNetworkType(d, nt)
					return d, lat, selected, nil
				}
			}
		}
		return nil, time.Hour, nil, ErrNoAliveDialer

	case consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		networkTypes, count := g.selectionNetworkTypes(networkType, policy)
		for i := range count {
			a := state.aliveDialerSets[networkTypes[i].Index()]
			d, latency := a.GetMinLatency(excluded)
			if d != nil {
				selected := preferAlternateSelectionNetworkType(d, &networkTypes[i])
				return d, latency, selected, nil
			}
		}
		return nil, time.Hour, nil, ErrNoAliveDialer

	default:
		return nil, 0, nil, fmt.Errorf("unsupported DialerSelectionPolicy: %v", policy)
	}
}

func (g *DialerGroup) selectionNetworkTypes(networkType *dialer.NetworkType, policy DialerSelectionPolicy) (networkTypes [3]dialer.NetworkType, count int) {
	networkTypes[0] = *networkType
	count = 1

	if policy.Policy == consts.DialerSelectionPolicy_Fixed ||
		policy.Policy == consts.DialerSelectionPolicy_FixedWithFallback ||
		networkType.L4Proto != consts.L4ProtoStr_UDP ||
		networkType.EffectiveUdpHealthDomain() != dialer.UdpHealthDomainData {
		return networkTypes, count
	}

	// If data-plane UDP has no alive dialer, retry selection against DNS UDP
	// first, then shared TCP health for the same IP family. A successful real
	// UDP flow will revive the data-UDP domain via ReportAvailableTraffic.
	networkTypes[count] = dialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       networkType.IpVersion,
		IsDns:           true,
		UdpHealthDomain: dialer.UdpHealthDomainDns,
	}
	count++
	networkTypes[count] = dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: networkType.IpVersion,
	}
	count++
	return networkTypes, count
}

func (g *DialerGroup) currentSelectionState() *dialerGroupSelectionState {
	state := g.selectionState.Load()
	if state == nil {
		return &dialerGroupSelectionState{}
	}
	return state
}

func (g *DialerGroup) buildSelectionState(policy DialerSelectionPolicy, setAlive bool) *dialerGroupSelectionState {
	state := &dialerGroupSelectionState{
		policy: policy,
	}
	if !policyNeedsAliveState(policy.Policy) {
		return state
	}

	// Determine the policy to use for AliveDialerSet creation.
	// FixedWithFallback uses its FallbackPolicy so latency is tracked
	// for min_moving_avg / min / random fallback selection.
	aliveSetPolicy := policy.Policy
	if policy.Policy == consts.DialerSelectionPolicy_FixedWithFallback {
		aliveSetPolicy = policy.FallbackPolicy
	}

	specs := standardSelectionNetworkTypes()
	keys := dialer.StandardHealthKeys()

	for i, nt := range specs {
		networkType := *nt
		set := dialer.NewAliveDialerSet(
			g.log, g.Name, &networkType, g.checkTolerance, aliveSetPolicy,
			g.Dialers, g.dialersAnnotations,
			func(networkType *dialer.NetworkType) func(alive bool) {
				return func(alive bool) { g.aliveChangeCallback(alive, networkType, false) }
			}(&networkType),
			false,
		)
		if setAlive {
			for _, d := range g.Dialers {
				set.NotifyLatencyChange(d, d.MustGetAlive(&networkType))
			}
		}
		state.aliveDialerSets[keys[i].CollectionIndex()] = set
		if networkType.L4Proto == consts.L4ProtoStr_TCP {
			if networkType.IpVersion == consts.IpVersionStr_4 {
				state.aliveDialerSets[dialer.IdxDnsTcp4] = set
			} else {
				state.aliveDialerSets[dialer.IdxDnsTcp6] = set
			}
		}
	}
	return state
}

func (g *DialerGroup) registerAliveDialerSets(aliveDialerSets [8]*dialer.AliveDialerSet) {
	for _, d := range g.Dialers {
		for _, a := range aliveDialerSets {
			d.RegisterAliveDialerSet(a)
		}
	}
}

func (g *DialerGroup) unregisterAliveDialerSets(aliveDialerSets [8]*dialer.AliveDialerSet) {
	for _, d := range g.Dialers {
		for _, a := range aliveDialerSets {
			d.UnregisterAliveDialerSet(a)
		}
	}
}

func policyNeedsAliveState(policy consts.DialerSelectionPolicy) bool {
	switch policy {
	case consts.DialerSelectionPolicy_Random,
		consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies,
		consts.DialerSelectionPolicy_FixedWithFallback:
		return true
	case consts.DialerSelectionPolicy_Fixed:
		return false
	default:
		panic(fmt.Sprintf("unexpected dialer selection policy: %v", policy))
	}
}

func uniqueAliveDialerSets(aliveDialerSets [8]*dialer.AliveDialerSet) []*dialer.AliveDialerSet {
	unique := make(map[*dialer.AliveDialerSet]struct{}, len(aliveDialerSets))
	var sets []*dialer.AliveDialerSet
	for _, set := range aliveDialerSets {
		if set == nil {
			continue
		}
		if _, ok := unique[set]; ok {
			continue
		}
		unique[set] = struct{}{}
		sets = append(sets, set)
	}
	return sets
}

func standardSelectionNetworkTypes() [6]*dialer.NetworkType {
	keys := dialer.StandardHealthKeys()
	var networkTypes [6]*dialer.NetworkType
	for i, key := range keys {
		networkTypes[i] = key.NetworkType()
	}
	return networkTypes
}

func preferAlternateSelectionNetworkType(d *dialer.Dialer, networkType *dialer.NetworkType) *dialer.NetworkType {
	if d == nil || networkType == nil {
		return networkType
	}
	if d.MustGetAlive(networkType) {
		return networkType
	}
	altType := alternateNetworkType(networkType)
	if altType == nil {
		return networkType
	}
	if d.MustGetAlive(altType) {
		return altType
	}
	return networkType
}

func alternateNetworkType(networkType *dialer.NetworkType) *dialer.NetworkType {
	if networkType == nil {
		return nil
	}
	switch networkType.IpVersion {
	case consts.IpVersionStr_4:
		alt := *networkType
		alt.IpVersion = consts.IpVersionStr_6
		return &alt
	case consts.IpVersionStr_6:
		alt := *networkType
		alt.IpVersion = consts.IpVersionStr_4
		return &alt
	default:
		return nil
	}
}

// runFixedFallbackRetry is a background goroutine that drives the
// timeout × retries cycle for the fixed_fallback policy independently
// of traffic. It fires probes at each FixedFallbackTimeout interval,
// and after maxRetries, marks the node for fallback.
func (g *DialerGroup) runFixedFallbackRetry(fixed *dialer.Dialer, policy DialerSelectionPolicy, nt *dialer.NetworkType) {
	defer g.fixedFallbackRunning.Store(false)

	actualTimeout := policy.FixedFallbackTimeout
	if actualTimeout < 2*time.Second {
		actualTimeout = 2 * time.Second
		g.log.WithFields(logrus.Fields{
			"group":        g.Name,
			"configured":   policy.FixedFallbackTimeout.String(),
			"actual":       actualTimeout.String(),
			"node":         fixed.Property().Name,
			"network_type": nt.String(),
		}).Warnln("fixed_fallback timeout too low, clamped to minimum 2s to prevent probe storm")
	}
	ticker := time.NewTicker(actualTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-g.fixedFallbackStopCh:
			return
		case <-ticker.C:
		}

		// Check if node has recovered
		if fixed.MustGetAlive(nt) {
			g.fixedFallbackMu.Lock()
			g.fixedFallbackDeadSince = 0
			g.fixedFallbackRetryCount = 0
			g.fixedFallbackMu.Unlock()
			return
		}

		// Advance retry count
		g.fixedFallbackMu.Lock()
		g.fixedFallbackRetryCount++
		g.fixedFallbackLastRetryNano = time.Now().UnixNano()

		shouldFallback := g.fixedFallbackRetryCount >= int64(policy.FixedFallbackRetries)
		if shouldFallback {
			// Make deadSince far in the past so any Select() immediately
			// sees elapsed >> timeout and falls back.
			g.fixedFallbackDeadSince = time.Now().UnixNano() -
				int64(policy.FixedFallbackTimeout)*int64(policy.FixedFallbackRetries) - 1
		} else {
			g.fixedFallbackDeadSince = time.Now().UnixNano()
		}
		g.fixedFallbackMu.Unlock()

		// Fire probes — also gives the node a chance to be marked alive
		// before the next tick.
		fixed.NotifyCheckTcp()
		fixed.NotifyCheckDnsUdp()

		if shouldFallback {
			g.logFixedFallback(-1, fixed, nt)
			return
		}
		g.logFixedFallback(10+g.fixedFallbackRetryCount, fixed, nt)
	}
}
