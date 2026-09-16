/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
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
	alivePublishMu      sync.Mutex

	resuscitateLastTime atomic.Int64
	noAliveLogLastTimes [8]atomic.Int64
	// alivePublishMissingSetCount counts availability publications that could
	// not revalidate a policy that needs alive state because this network type
	// has no AliveDialerSet. The last published value is kept in that case, so
	// the counter (plus its rate-limited log) is the only signal that the
	// revalidation contract broke.
	alivePublishMissingSetCount atomic.Uint64

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

	for _, nt := range standardSelectionNetworkTypes() {
		group.publishAliveChange(true, nt, true)
	}

	return group
}

func (g *DialerGroup) Close() error {
	g.unregisterAliveDialerSets(g.currentSelectionState().aliveDialerSets)
	return nil
}

// SnapshotForEstablishedFlow returns a compact immutable view of the group
// decision retained by an established flow. It deliberately omits health sets
// and every unselected dialer so a long-lived flow cannot retain the full
// retired generation.
func (g *DialerGroup) SnapshotForEstablishedFlow(selected *dialer.Dialer) *DialerGroup {
	if g == nil {
		return nil
	}
	view := &DialerGroup{
		log:                    g.log,
		Name:                   g.Name,
		cachedMinCheckInterval: g.cachedMinCheckInterval,
	}
	if selected != nil {
		view.Dialer = selected
		view.Dialers = []*dialer.Dialer{selected}
	}
	view.selectionState.Store(&dialerGroupSelectionState{
		policy: g.currentSelectionState().policy,
	})
	return view
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
		g.logNoAlive(origNetworkType, selectionNetworkType, src, dst, domain, logInterval)
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

func (g *DialerGroup) logNoAlive(
	origNetworkType string,
	selectionNetworkType *dialer.NetworkType,
	src netip.AddrPort,
	dst netip.AddrPort,
	domain string,
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
		d, latency, selectedNetworkType, err = g._select(&nt, state, policy, excluded)
		// Do not return early on failure: the single-dialer fallback below is
		// an availability floor and must not be bypassed by the lenient path
		// (which should never be worse than the strict one).
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

	specs := standardSelectionNetworkTypes()
	keys := dialer.StandardHealthKeys()

	for i, nt := range specs {
		networkType := *nt
		set := dialer.NewAliveDialerSet(
			g.log, g.Name, &networkType, g.checkTolerance, policy.Policy,
			g.Dialers, g.dialersAnnotations,
			func(networkType *dialer.NetworkType) func(alive bool) {
				return func(alive bool) { g.publishAliveChange(alive, networkType, false) }
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

// publishAliveChange forwards a group availability transition to the
// aliveChangeCallback after revalidating it against the set's current
// membership. AliveDialerSet fires its callback outside the set lock, so the
// bool only describes the state at transition time: a notification that lags
// behind a concurrent flip (e.g. a death callback paused while a revival
// completes) would otherwise publish a historical value and could regress the
// kernel outbound-connectivity map away from the current truth. Re-deriving
// the bool from the set's membership at publication time keeps every write
// consistent with the latest state, so the map converges on the final truth
// and cannot be left at 0 for a group that is alive again - data-UDP domains
// have no periodic probe that would repair it. Init publications are exempt:
// a fresh group publishes optimistic aliveness before its health converges.
func (g *DialerGroup) publishAliveChange(alive bool, networkType *dialer.NetworkType, isInit bool) {
	if g == nil || g.aliveChangeCallback == nil {
		return
	}
	// Set callbacks intentionally run outside AliveDialerSet's lock. Serialize
	// the membership revalidation with the callback so an older notification
	// cannot publish after a newer revival has already reached the datapath.
	g.alivePublishMu.Lock()
	defer g.alivePublishMu.Unlock()

	if !isInit {
		switch set := g.MustGetAliveDialerSet(networkType); {
		case set != nil:
			alive = set.Len() > 0
		case groupPublishesOptimisticAlive(g.GetSelectionPolicy()):
			// Fixed and Random select in userspace and never need the kernel to
			// gate admission for the group, so a missing set means "publish
			// alive" - exactly what the connectivity publication path does for
			// these policies. Trusting the incoming bool here could write 0 and
			// strand a perfectly usable group with no probe to repair it
			// (Fixed has no alive set at all).
			alive = true
		case policyRevalidatesAliveState(g.GetSelectionPolicy()):
			// Policy needs per-dialer alive state but this network type has no
			// set: the incoming bool cannot be revalidated, so publishing it
			// could regress the kernel connectivity slot to 0 for a live group.
			// Keep the last published value (publish nothing), count, and log.
			count := g.alivePublishMissingSetCount.Add(1)
			if count&(count-1) == 0 && g.log != nil {
				g.log.WithFields(logrus.Fields{
					"group":       g.Name,
					"network":     networkType.String(),
					"policy":      g.GetSelectionPolicy(),
					"notified":    alive,
					"occurrences": count,
				}).Error("availability notification has no AliveDialerSet to revalidate against; keeping the last published value")
			}
			return
		default:
			// No published selection policy yet (the group's first state is
			// still being built, so its sets are not reachable through
			// MustGetAliveDialerSet). There is no membership to revalidate
			// against and no previous value to keep: trust the notification,
			// exactly as before.
		}
	}
	g.aliveChangeCallback(alive, networkType, isInit)
}

// groupPublishesOptimisticAlive reports whether the group's selection policy
// keeps the kernel outbound-connectivity slot open regardless of per-dialer
// health. Fixed and Random pick in userspace, so the kernel must always admit
// flows for the group (mirrors resumeOutboundConnectivityUpdates).
func groupPublishesOptimisticAlive(policy consts.DialerSelectionPolicy) bool {
	switch policy {
	case consts.DialerSelectionPolicy_Fixed, consts.DialerSelectionPolicy_Random:
		return true
	default:
		return false
	}
}

// policyRevalidatesAliveState reports whether the policy derives selection from
// per-dialer alive state, i.e. whether a missing AliveDialerSet makes the
// notification unsafe to publish. Deliberately distinct from
// policyNeedsAliveState, which panics on the zero policy value that a
// still-unpublished selection state reports.
func policyRevalidatesAliveState(policy consts.DialerSelectionPolicy) bool {
	switch policy {
	case consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		return true
	default:
		return false
	}
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
		consts.DialerSelectionPolicy_MinMovingAverageLatencies:
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
