/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/daedns"
	"github.com/daeuniverse/dae/config"
	D "github.com/daeuniverse/outbound/dialer"
	stickyip "github.com/daeuniverse/outbound/dialer/stickyip"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

// Connectivity check indices.
//
// DESIGN NOTE: TCP DNS and plain TCP share the same health check result because they
// are identical at the transport layer (both use TCP). The Index() method returns
// IdxTcp4/IdxTcp6 for both TCP DNS and plain TCP network types.
//
// IdxDnsTcp4 and IdxDnsTcp6 constants are kept for backward compatibility and are used
// as aliases to access the shared AliveDialerSet/collection. When a dialer needs to
// check TCP DNS connectivity, it uses the same result as plain TCP (IdxTcp4/IdxTcp6).
//
// UDP health is split into two domains:
//   - DNS UDP: DNS request / probe paths
//   - Data UDP: proxied application traffic such as QUIC and games
//
// Memory layout:
//   - [0] IdxDnsTcp4 -> aliases to [4] IdxTcp4
//   - [1] IdxDnsTcp6 -> aliases to [5] IdxTcp6
//   - [2] IdxDnsUdp4 -> independent UDP DNS IPv4 check
//   - [3] IdxDnsUdp6 -> independent UDP DNS IPv6 check
//   - [4] IdxTcp4    -> TCP IPv4 check (shared with TCP DNS)
//   - [5] IdxTcp6    -> TCP IPv6 check (shared with TCP DNS)
//   - [6] IdxUdp4    -> independent data UDP IPv4 health
//   - [7] IdxUdp6    -> independent data UDP IPv6 health
const (
	IdxDnsTcp4 = 0
	IdxDnsTcp6 = 1
	IdxDnsUdp4 = 2
	IdxDnsUdp6 = 3
	IdxTcp4    = 4
	IdxTcp6    = 5
	IdxUdp4    = 6
	IdxUdp6    = 7

	idxTcp     = 0
	idxDnsUdp  = 1
	idxDataUdp = 2
)

var (
	ErrUnexpectedField  = fmt.Errorf("unexpected field")
	ErrInvalidParameter = fmt.Errorf("invalid parameters")
)

var cachedTimeNano atomic.Int64

func init() {
	cachedTimeNano.Store(time.Now().UnixNano())
	go func() {
		ticker := time.NewTicker(time.Second)
		for range ticker.C {
			cachedTimeNano.Store(time.Now().UnixNano())
		}
	}()
}

func CachedTimeNano() int64 {
	return cachedTimeNano.Load()
}

type Dialer struct {
	*GlobalOption
	InstanceOption
	netproxy.Dialer
	property *Property

	collectionFineMu sync.RWMutex
	collections      [8]*collection

	aliveTransitionMu        sync.RWMutex
	aliveTransitionCallbacks []func(networkType *NetworkType, alive bool)

	tickerMu      sync.Mutex
	ticker        *time.Timer
	checkCh       chan time.Time
	checkDnsUdpCh chan struct{} // trigger resuscitation for DNS-UDP collections (IPv4+v6)
	checkTcpCh    chan struct{} // trigger resuscitation for all TCP collections (IPv4+v6)
	ctx           context.Context
	cancel        context.CancelFunc

	checkActivated bool

	httpClients  map[string]*http.Client
	httpClientMu sync.Mutex

	failCount        [8]int
	trafficFailCount [8]atomic.Int32

	// stickyIpDialer holds reference to the sticky IP wrapper for cache management
	// This is used for health check cycle management and failover tracking
	stickyIpDialer *stickyip.StickyIpDialer
	proxyIpCache   *ProxyIpCache

	// recoveryState manages exponential backoff for recovery detection.
	// It is intentionally scoped to a single dialer instance so cloned or
	// recreated dialers start clean under their own health-check semantics.
	// Reload snapshots may explicitly restore this state into a replacement
	// dialer to keep health selection seamless across generations.
	// Domains:
	//   0: TCP
	//   1: DNS UDP
	//   2: Data UDP
	recoveryState [3]struct {
		sync.Mutex

		// backoffLevel indicates current backoff level (0, 1, 2, 3...)
		// Backoff duration = minBackoff * (2 ^ level), capped at maxBackoff
		backoffLevel int

		// stableSuccessCount is the number of consecutive stable periodic checks
		// When this reaches 6, backoffLevel is decremented.
		stableSuccessCount int

		// maxBackoff is the maximum backoff duration, calculated based on check interval
		// This is set during initialization and prevents overlap with health checks
		maxBackoff time.Duration

		// confirmTimer is the scheduled timer to confirm recovery after backoff period
		confirmTimer *time.Timer

		// pendingNetworkType is the network type being verified for recovery
		pendingNetworkType *NetworkType

		// confirmDeadlineUnixNano tracks when the current confirmation timer
		// should fire so reload snapshots can restore the remaining delay.
		confirmDeadlineUnixNano int64
	}
	lastNotifyUdp atomic.Int64
	lastNotifyTcp atomic.Int64
	lastPunish    [3]atomic.Int64
}

type DialerCollectionHealthSnapshot struct {
	Alive            bool
	MovingAverage    time.Duration
	Latencies        LatenciesNSnapshot
	FailCount        int
	TrafficFailCount int32
}

type DialerRecoveryHealthSnapshot struct {
	BackoffLevel        int
	StableSuccessCount  int
	PendingNetworkType  *NetworkType
	PendingConfirmDelay time.Duration
	LastPunishUnixNano  int64
}

type DialerHealthSnapshot struct {
	Collections [8]DialerCollectionHealthSnapshot
	Recovery    [3]DialerRecoveryHealthSnapshot
}

type GlobalOption struct {
	D.ExtraOption
	Log               *logrus.Logger
	DaeDNS            *daedns.Router
	TcpCheckOptionRaw TcpCheckOptionRaw // Lazy parse
	CheckDnsOptionRaw CheckDnsOptionRaw // Lazy parse
	CheckInterval     time.Duration
	CheckTolerance    time.Duration
	CheckDnsTcp       bool
	SoMarkFromDae     uint32
	Mptcp             bool
}

type InstanceOption struct {
	DisableCheck bool
}

type Property struct {
	D.Property
	SubscriptionTag string
}

const (
	// Recovery detection exponential backoff constants
	// minRecoveryBackoff is the initial backoff duration for recovery confirmation
	minRecoveryBackoff = 10 * time.Second
	// maxRecoveryBackoff is the maximum backoff duration (should be < health check interval)
	// This prevents infinite amplification with periodic health checks
	// backoffMultiplier is the factor to increase backoff duration after each level
	backoffMultiplier = 2
)

type AliveDialerSetSet map[*AliveDialerSet]int

func NewGlobalOption(global *config.Global, log *logrus.Logger) *GlobalOption {
	soMarkFromDae := common.EffectiveSoMarkFromDae(global.SoMarkFromDae)
	return &GlobalOption{
		ExtraOption: D.ExtraOption{
			AllowInsecure:       global.AllowInsecure,
			TlsImplementation:   global.TlsImplementation,
			UtlsImitate:         global.UtlsImitate,
			BandwidthMaxTx:      global.BandwidthMaxTx,
			BandwidthMaxRx:      global.BandwidthMaxRx,
			TlsFragment:         global.TlsFragment,
			TlsFragmentLength:   global.TlsFragmentLength,
			TlsFragmentInterval: global.TlsFragmentInterval,
			UDPHopInterval:      global.UDPHopInterval,
		},
		Log:               log,
		TcpCheckOptionRaw: TcpCheckOptionRaw{Raw: global.TcpCheckUrl, Log: log, ResolverNetwork: common.MagicNetwork("udp", soMarkFromDae, global.Mptcp), Method: global.TcpCheckHttpMethod},
		CheckDnsOptionRaw: CheckDnsOptionRaw{Raw: global.UdpCheckDns, ResolverNetwork: common.MagicNetwork("udp", soMarkFromDae, global.Mptcp), Somark: soMarkFromDae},
		CheckInterval:     global.CheckInterval,
		CheckTolerance:    global.CheckTolerance,
		CheckDnsTcp:       true,
		SoMarkFromDae:     soMarkFromDae,
		Mptcp:             global.Mptcp,
	}
}

// NewDialer is for register in general.
func NewDialer(dialer netproxy.Dialer, option *GlobalOption, iOption InstanceOption, property *Property) *Dialer {
	return NewDialerContext(context.Background(), dialer, option, iOption, property)
}

// NewDialerContext is for internal use with lifecycle management.
func NewDialerContext(ctx context.Context, dialer netproxy.Dialer, option *GlobalOption, iOption InstanceOption, property *Property) *Dialer {
	var collections [8]*collection
	for _, i := range []int{IdxDnsUdp4, IdxDnsUdp6, IdxTcp4, IdxTcp6, IdxUdp4, IdxUdp6} {
		collections[i] = newCollection()
	}
	collections[IdxDnsTcp4] = collections[IdxTcp4]
	collections[IdxDnsTcp6] = collections[IdxTcp6]

	ctx, cancel := context.WithCancel(ctx)
	d := &Dialer{
		GlobalOption:     option,
		InstanceOption:   iOption,
		property:         property,
		collectionFineMu: sync.RWMutex{},
		collections:      collections,
		tickerMu:         sync.Mutex{},
		ticker:           nil,
		checkCh:          make(chan time.Time, 1),
		checkDnsUdpCh:    make(chan struct{}, 1),
		checkTcpCh:       make(chan struct{}, 1),
		ctx:              ctx,
		cancel:           cancel,
		httpClients:      make(map[string]*http.Client),
	}
	d.Dialer = dialer

	// Initialize recovery detection with adjusted max backoff
	d.initRecoveryDetection(option.CheckInterval)

	option.Log.WithField("dialer", d.Property().Name).
		WithField("p", unsafe.Pointer(d)).
		Traceln("NewDialer")
	return d
}

// Clone returns a new dialer instance with the same GlobalOption.
func (d *Dialer) Clone() *Dialer {
	return d.CloneWithGlobalOption(d.GlobalOption)
}

// CloneWithGlobalOption returns a new dialer instance initialized with option.
func (d *Dialer) CloneWithGlobalOption(option *GlobalOption) *Dialer {
	return d.CloneWithGlobalOptionContext(d.ctx, option)
}

// CloneWithGlobalOptionContext returns a new dialer instance initialized with option.
func (d *Dialer) CloneWithGlobalOptionContext(ctx context.Context, option *GlobalOption) *Dialer {
	if d.property != nil && d.property.Link != "" {
		clone, err := NewFromLinkWithProxyCacheContext(ctx, option, d.InstanceOption, d.property.Link, d.property.SubscriptionTag, NewProxyIpCache())
		if err == nil {
			clone.property = cloneProperty(d.property)
			return clone
		}
		if option != nil && option.Log != nil {
			option.Log.WithError(err).
				WithField("dialer", d.Property().Name).
				Warnln("Failed to reconstruct dialer clone from link; falling back to shared dialer instance")
		}
	}

	clone := NewDialerContext(ctx, d.Dialer, option, d.InstanceOption, cloneProperty(d.property))
	clone.stickyIpDialer = d.stickyIpDialer
	clone.proxyIpCache = d.proxyIpCache
	return clone
}

func (d *Dialer) Close() error {
	d.cancel()
	if d.property != nil {
		unregisterProxyCache(d.property.Address, d.proxyIpCache)
	}

	// Cancel any pending recovery confirmation to prevent timer leaks
	d.cancelPendingRecoveryConfirmation(consts.L4ProtoStr_TCP)
	d.cancelPendingRecoveryConfirmationForType(&NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		IsDns:           true,
		UdpHealthDomain: UdpHealthDomainDns,
	})
	d.cancelPendingRecoveryConfirmationForType(&NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		UdpHealthDomain: UdpHealthDomainData,
	})

	d.tickerMu.Lock()
	if d.ticker != nil {
		d.ticker.Stop()
	}
	d.tickerMu.Unlock()

	d.httpClientMu.Lock()
	for k, cli := range d.httpClients {
		if cli != nil {
			cli.CloseIdleConnections()
			// Further help the Go GC by clearing the pool reference.
			if t, ok := cli.Transport.(*http.Transport); ok {
				t.CloseIdleConnections()
			}
			delete(d.httpClients, k)
		}
	}
	d.httpClientMu.Unlock()

	// If the underlying dialer supports explicit closure (common for QUIC/Hysteria2),
	// call it to retire background workers immediately.
	if closer, ok := d.Dialer.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	return nil
}

func (d *Dialer) Property() *Property {
	return d.property
}

func cloneProperty(property *Property) *Property {
	if property == nil {
		return nil
	}
	cloned := *property
	return &cloned
}

func (d *Dialer) RegisterAliveTransitionCallback(callback func(networkType *NetworkType, alive bool)) {
	if callback == nil {
		return
	}
	d.aliveTransitionMu.Lock()
	d.aliveTransitionCallbacks = append(d.aliveTransitionCallbacks, callback)
	d.aliveTransitionMu.Unlock()
}

func (d *Dialer) notifyAliveTransition(networkType *NetworkType, alive bool) {
	d.aliveTransitionMu.RLock()
	if len(d.aliveTransitionCallbacks) == 0 {
		d.aliveTransitionMu.RUnlock()
		return
	}
	callbacks := append([]func(networkType *NetworkType, alive bool){}, d.aliveTransitionCallbacks...)
	d.aliveTransitionMu.RUnlock()

	networkTypeCopy := *networkType
	for _, callback := range callbacks {
		callback(&networkTypeCopy, alive)
	}
}

func networkTypeForCollectionIndex(idx int) *NetworkType {
	switch idx {
	case IdxDnsTcp4:
		return &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4, IsDns: true}
	case IdxDnsTcp6:
		return &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_6, IsDns: true}
	case IdxDnsUdp4:
		return &NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, IsDns: true, UdpHealthDomain: UdpHealthDomainDns}
	case IdxDnsUdp6:
		return &NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_6, IsDns: true, UdpHealthDomain: UdpHealthDomainDns}
	case IdxTcp4:
		return &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	case IdxTcp6:
		return &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_6}
	case IdxUdp4:
		return &NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, UdpHealthDomain: UdpHealthDomainData}
	case IdxUdp6:
		return &NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_6, UdpHealthDomain: UdpHealthDomainData}
	default:
		return nil
	}
}

func cloneNetworkType(networkType *NetworkType) *NetworkType {
	if networkType == nil {
		return nil
	}
	cloned := *networkType
	return &cloned
}

func (d *Dialer) HealthSnapshot() DialerHealthSnapshot {
	var snapshot DialerHealthSnapshot
	if d == nil {
		return snapshot
	}

	d.collectionFineMu.RLock()
	defer d.collectionFineMu.RUnlock()
	for idx, collection := range d.collections {
		if collection == nil {
			continue
		}
		snapshot.Collections[idx] = DialerCollectionHealthSnapshot{
			Alive:            collection.Alive.Load(),
			MovingAverage:    collection.MovingAverage,
			Latencies:        collection.Latencies10.Snapshot(),
			FailCount:        d.failCount[idx],
			TrafficFailCount: d.trafficFailCount[idx].Load(),
		}
	}
	nowNano := time.Now().UnixNano()
	for idx := range d.recoveryState {
		state := &d.recoveryState[idx]
		state.Lock()
		snapshot.Recovery[idx] = DialerRecoveryHealthSnapshot{
			BackoffLevel:       state.backoffLevel,
			StableSuccessCount: state.stableSuccessCount,
			LastPunishUnixNano: d.lastPunish[idx].Load(),
		}
		if state.confirmTimer != nil && state.pendingNetworkType != nil && state.confirmDeadlineUnixNano > nowNano {
			snapshot.Recovery[idx].PendingNetworkType = cloneNetworkType(state.pendingNetworkType)
			snapshot.Recovery[idx].PendingConfirmDelay = time.Duration(state.confirmDeadlineUnixNano - nowNano)
		}
		state.Unlock()
	}
	return snapshot
}

func (d *Dialer) RestoreHealthSnapshot(snapshot DialerHealthSnapshot) {
	if d == nil {
		return
	}

	type restoreUpdate struct {
		typ    *NetworkType
		was    bool
		alive  bool
		groups []*AliveDialerSet
	}

	updates := make([]restoreUpdate, 0, len(d.collections))
	d.collectionFineMu.Lock()
	for idx, collection := range d.collections {
		if collection == nil {
			continue
		}
		s := snapshot.Collections[idx]
		wasAlive := collection.Alive.Load()
		collection.Alive.Store(s.Alive)
		collection.MovingAverage = s.MovingAverage
		collection.Latencies10.Restore(s.Latencies)
		d.failCount[idx] = s.FailCount
		d.trafficFailCount[idx].Store(s.TrafficFailCount)
		updates = append(updates, restoreUpdate{
			typ:    networkTypeForCollectionIndex(idx),
			was:    wasAlive,
			alive:  s.Alive,
			groups: d.snapshotAliveDialerGroupsLocked(collection),
		})
	}
	d.collectionFineMu.Unlock()

	for _, update := range updates {
		for _, a := range update.groups {
			a.NotifyLatencyChange(d, update.alive)
		}
		if update.typ != nil && update.was != update.alive {
			d.notifyAliveTransition(update.typ, update.alive)
		}
	}

	for idx := range d.recoveryState {
		recoverySnapshot := snapshot.Recovery[idx]
		state := &d.recoveryState[idx]
		state.Lock()
		if state.confirmTimer != nil {
			state.confirmTimer.Stop()
			state.confirmTimer = nil
		}
		state.pendingNetworkType = nil
		state.confirmDeadlineUnixNano = 0
		state.backoffLevel = recoverySnapshot.BackoffLevel
		state.stableSuccessCount = recoverySnapshot.StableSuccessCount
		state.Unlock()

		d.lastPunish[idx].Store(recoverySnapshot.LastPunishUnixNano)
		if recoverySnapshot.PendingNetworkType == nil {
			continue
		}
		delay := recoverySnapshot.PendingConfirmDelay
		if delay < 0 {
			delay = 0
		}
		maxDelay := d.getRecoveryBackoffDurationByIndex(idx)
		if maxDelay > 0 && delay > maxDelay {
			delay = maxDelay
		}
		d.armRecoveryConfirmationFromSnapshot(idx, recoverySnapshot.PendingNetworkType, delay)
	}
}

// IncrementCheckCycle advances the health check cycle for sticky IP caching.
// This is called by the health checker to advance the cycle and invalidate
// old cache entries, allowing IP failover to different resolved IPs.
func (d *Dialer) IncrementCheckCycle() {
	if d.stickyIpDialer != nil {
		d.stickyIpDialer.IncrementCheckCycle()
	}
}

// NotifyHealthCheckResult notifies about health check results.
// On success: clears failed QUIC DCID cache, resets proxy IP failure counter, and triggers recovery detection if revival.
// On failure: tracks consecutive failures and trims stability counter.
func (d *Dialer) NotifyHealthCheckResult(typ *NetworkType, success bool, isRevival bool) {
	if success {
		// Reset proxy IP failure counter on success
		if d.property.Address != "" {
			recordProxySuccess(d.property.Address)
		}
		// Clear failed QUIC DCID cache
		notifyQuicDcidCacheClearImpl()

		// Trigger recovery detection with exponential backoff ONLY on TRUE transition from Dead to Alive
		// isRevival parameter comes from markAvailable and currently includes isResuscitation.
		// We no longer trigger detection for emergency probes on already-healthy nodes.
		if isRevival {
			d.triggerRecoveryDetection(typ)
		}
	} else {
		// Increment backoff level on any failure (Punishment)
		d.incrementBackoffLevelForType(typ)

		// Reset stability counter on any failure (Trust Level Reset)
		d.resetStabilityCountForType(typ)

		// Cancel any pending recovery confirmation to prevent premature recovery
		// if the node revives again before the original timer fires.
		d.cancelPendingRecoveryConfirmationForType(typ)

		// Track failures - may trigger immediate unavailability
		if d.property.Address != "" {
			if recordProxyFailure(d.property.Address) {
				// Threshold reached - immediately mark dialer as unavailable
				// This bypasses the 30-second health check cycle for faster failover
				d.markUnavailableFromProxyFailure()
			}
		}
	}
}

func (d *Dialer) recoveryIdxForType(typ *NetworkType) int {
	if typ == nil || typ.L4Proto == consts.L4ProtoStr_TCP {
		return idxTcp
	}
	if typ.EffectiveUdpHealthDomain() == UdpHealthDomainDns {
		return idxDnsUdp
	}
	return idxDataUdp
}

func (d *Dialer) protoIdx(proto consts.L4ProtoStr) int {
	if proto == consts.L4ProtoStr_UDP {
		return idxDnsUdp
	}
	return idxTcp
}

// NotifyProxyFailure is called when a proxy server connection fails (e.g., connection refused).
// It immediately invalidates the cached IP for the failed protocol and address family so that
// the next connection can try a different IP without discarding healthy families.
func (d *Dialer) NotifyProxyFailure(proxyAddr string, networkType *NetworkType) {
	if d.stickyIpDialer == nil {
		return
	}
	if networkType == nil {
		return
	}
	if networkType.IpVersion != "" {
		d.stickyIpDialer.InvalidateProtocolAndIpVersionCache(proxyAddr, string(networkType.L4Proto), string(networkType.IpVersion))
		return
	}
	d.stickyIpDialer.InvalidateProtocolCache(proxyAddr, string(networkType.L4Proto))
}

// notifyQuicDcidCacheClearImpl is the actual implementation.
// It's defined as a var that gets initialized at runtime to avoid circular dependency.
var notifyQuicDcidCacheClearImpl func() = func() {
	// Default implementation does nothing
	// Will be overridden by control package during initialization
}

// SetQuicDcidCacheClearFunc sets the function to clear failed QUIC DCID cache.
// This should be called by control package during initialization.
func SetQuicDcidCacheClearFunc(fn func()) {
	notifyQuicDcidCacheClearImpl = fn
}

// Recovery detection methods

// initRecoveryDetection initializes recovery detection with adjusted max backoff based on health check interval.
// This prevents infinite amplification between periodic health checks and recovery confirmation timers.
func (d *Dialer) initRecoveryDetection(checkInterval time.Duration) {
	// Max backoff should be < health check interval to prevent overlap
	// Use 2/3 of check interval to leave room for confirmation
	maxBackoff := time.Duration(float64(checkInterval) * 2.0 / 3.0)
	if maxBackoff < minRecoveryBackoff {
		maxBackoff = minRecoveryBackoff
	}

	for i := range d.recoveryState {
		d.recoveryState[i].Lock()
		d.recoveryState[i].maxBackoff = maxBackoff
		d.recoveryState[i].Unlock()
	}

	d.Log.WithFields(logrus.Fields{
		"dialer":         d.Property().Name,
		"check_interval": checkInterval.String(),
		"max_backoff":    maxBackoff.String(),
	}).Debugln("Recovery detection initialized")
}

// triggerRecoveryDetection triggers recovery detection with exponential backoff.
// This is called when health check succeeds, to verify the dialer is truly stable before marking it healthy.
func (d *Dialer) triggerRecoveryDetection(typ *NetworkType) {
	d.triggerRecoveryDetectionInternal(typ)
}

func (d *Dialer) triggerRecoveryDetectionInternal(target *NetworkType) {
	// Check context first to avoid scheduling recovery on a closed dialer
	select {
	case <-d.ctx.Done():
		d.Log.WithFields(logrus.Fields{
			"dialer": d.Property().Name,
		}).Traceln("Recovery detection skipped: dialer is shutting down")
		return
	default:
	}

	protoIdx := d.recoveryIdxForType(target)
	d.recoveryState[protoIdx].Lock()
	defer d.recoveryState[protoIdx].Unlock()

	// Skip if confirmation timer already running (prevent duplicate triggers)
	if d.recoveryState[protoIdx].confirmTimer != nil {
		d.Log.WithFields(logrus.Fields{
			"dialer": d.Property().Name,
			"proto":  target.L4Proto,
		}).Traceln("Recovery detection already in progress, skip")
		return
	}

	networkType := target

	// NOTE: We no longer skip if already healthy, because the caller (markAvailable)
	// now provides an explicit isRevival flag. If we are here, it's a confirmed revival.

	// Calculate backoff duration based on current level
	backoff := d.calculateBackoffDurationLocked(d.recoveryState[protoIdx].backoffLevel, d.recoveryState[protoIdx].maxBackoff)

	d.Log.WithFields(logrus.Fields{
		"dialer":        d.Property().Name,
		"network":       networkType.String(),
		"backoff":       backoff.String(),
		"backoff_level": d.recoveryState[protoIdx].backoffLevel,
	}).Debugln("Recovery detection scheduled with exponential backoff")

	// Schedule confirmation timer
	d.recoveryState[protoIdx].pendingNetworkType = cloneNetworkType(networkType)
	d.recoveryState[protoIdx].confirmDeadlineUnixNano = time.Now().Add(backoff).UnixNano()
	var timer *time.Timer
	timer = time.AfterFunc(backoff, func() {
		d.confirmRecovery(networkType, timer)
	})
	d.recoveryState[protoIdx].confirmTimer = timer
}

func (d *Dialer) armRecoveryConfirmationFromSnapshot(protoIdx int, target *NetworkType, delay time.Duration) {
	if d == nil || target == nil {
		return
	}
	select {
	case <-d.ctx.Done():
		return
	default:
	}
	if delay < 0 {
		delay = 0
	}

	networkType := cloneNetworkType(target)
	if networkType == nil {
		return
	}

	state := &d.recoveryState[protoIdx]
	state.Lock()
	defer state.Unlock()
	if state.confirmTimer != nil {
		state.confirmTimer.Stop()
		state.confirmTimer = nil
	}
	state.pendingNetworkType = cloneNetworkType(networkType)
	state.confirmDeadlineUnixNano = time.Now().Add(delay).UnixNano()
	var timer *time.Timer
	timer = time.AfterFunc(delay, func() {
		d.confirmRecovery(networkType, timer)
	})
	state.confirmTimer = timer
}

// confirmRecovery confirms recovery after backoff period.
// It checks if the dialer is still healthy before confirming.
func (d *Dialer) confirmRecovery(networkType *NetworkType, timer *time.Timer) {
	// CRITICAL: Check context first to avoid accessing closed resources
	// after SIGTERM/SIGINT. This prevents goroutines from running after
	// the dialer has been partially closed.
	select {
	case <-d.ctx.Done():
		d.Log.WithFields(logrus.Fields{
			"dialer":  d.Property().Name,
			"network": networkType.String(),
		}).Debugln("Recovery confirmation aborted: dialer is shutting down")
		return
	default:
	}

	protoIdx := d.recoveryIdxForType(networkType)
	d.recoveryState[protoIdx].Lock()
	// Clear timer safely (compare-and-nil) to avoid racing with a NEW timer
	// scheduled by a concurrent revival.
	if d.recoveryState[protoIdx].confirmTimer == timer {
		d.recoveryState[protoIdx].confirmTimer = nil
		d.recoveryState[protoIdx].confirmDeadlineUnixNano = 0
		d.recoveryState[protoIdx].pendingNetworkType = nil
	}
	// Snapshot backoff level while holding lock to detect concurrent resets
	currentBackoffLevel := d.recoveryState[protoIdx].backoffLevel
	d.recoveryState[protoIdx].Unlock()

	// CRITICAL: Check context again after releasing lock
	select {
	case <-d.ctx.Done():
		d.Log.WithFields(logrus.Fields{
			"dialer":  d.Property().Name,
			"network": networkType.String(),
		}).Debugln("Recovery confirmation aborted: dialer is shutting down")
		return
	default:
	}

	// Double-check if still healthy (might have failed during backoff period)
	d.recoveryState[protoIdx].Lock()
	alive := d.isRecoveryTypeAlive(networkType)
	if !alive {
		d.recoveryState[protoIdx].Unlock()
		d.Log.WithFields(logrus.Fields{
			"dialer":  d.Property().Name,
			"proto":   networkType.L4Proto,
			"network": networkType.String(),
		}).Debugln("Recovery confirmation failed: all IP versions unhealthy, will retry on next health check")
		return
	}

	// Confirm recovery - decrease backoff level as a reward for stability
	// Only decrement if level hasn't been reset by a concurrent failure
	if d.recoveryState[protoIdx].backoffLevel == currentBackoffLevel {
		if d.recoveryState[protoIdx].backoffLevel > 0 {
			d.recoveryState[protoIdx].backoffLevel--
		}
		d.Log.WithFields(logrus.Fields{
			"dialer":        d.Property().Name,
			"proto":         networkType.L4Proto,
			"network":       networkType.String(),
			"backoff_level": d.recoveryState[protoIdx].backoffLevel,
		}).Infoln("Recovery confirmed after exponential backoff: penalty decreased")
	} else {
		// Level was reset by concurrent failure, don't decrement
		d.Log.WithFields(logrus.Fields{
			"dialer":        d.Property().Name,
			"network":       networkType.String(),
			"backoff_level": d.recoveryState[protoIdx].backoffLevel,
		}).Debugln("Recovery confirmation skipped: backoff level was reset by concurrent failure")
	}
	d.recoveryState[protoIdx].Unlock()

	// Note: We don't call markAvailable() here because periodic health check
	// will naturally update the dialer state. This just confirms the recovery is genuine.
}

// cancelPendingRecoveryConfirmation cancels any pending recovery confirmation timer for a specific protocol.
// This is called when the dialer fails again during recovery observation period.
func (d *Dialer) cancelPendingRecoveryConfirmation(proto consts.L4ProtoStr) {
	protoIdx := d.protoIdx(proto)
	d.cancelPendingRecoveryConfirmationByIndex(protoIdx, proto)
}

func (d *Dialer) cancelPendingRecoveryConfirmationForType(typ *NetworkType) {
	if typ == nil {
		return
	}
	protoIdx := d.recoveryIdxForType(typ)
	d.cancelPendingRecoveryConfirmationByIndex(protoIdx, typ.L4Proto)
}

func (d *Dialer) cancelPendingRecoveryConfirmationByIndex(protoIdx int, proto consts.L4ProtoStr) {
	d.recoveryState[protoIdx].Lock()
	defer d.recoveryState[protoIdx].Unlock()

	if d.recoveryState[protoIdx].confirmTimer != nil {
		d.recoveryState[protoIdx].confirmTimer.Stop()
		d.recoveryState[protoIdx].confirmTimer = nil
		d.recoveryState[protoIdx].confirmDeadlineUnixNano = 0
		d.recoveryState[protoIdx].pendingNetworkType = nil

		d.Log.WithFields(logrus.Fields{
			"dialer": d.Property().Name,
			"proto":  proto,
		}).Debugln("Pending recovery confirmation cancelled due to new failure")
	}
}

// getRecoveryBackoffDuration returns the backoff duration based on current level for a protocol.
// Thread-safe: acquires lock to read backoffLevel and maxBackoff.
func (d *Dialer) getRecoveryBackoffDuration(proto consts.L4ProtoStr) time.Duration {
	protoIdx := d.protoIdx(proto)
	return d.getRecoveryBackoffDurationByIndex(protoIdx)
}

func (d *Dialer) getRecoveryBackoffDurationByIndex(protoIdx int) time.Duration {
	d.recoveryState[protoIdx].Lock()
	defer d.recoveryState[protoIdx].Unlock()

	return d.calculateBackoffDurationLocked(d.recoveryState[protoIdx].backoffLevel, d.recoveryState[protoIdx].maxBackoff)
}

// calculateBackoffDurationLocked calculates the backoff duration without acquiring a lock.
// The caller must hold recoveryState.Lock() when calling this method.
func (d *Dialer) calculateBackoffDurationLocked(level int, maxBackoff time.Duration) time.Duration {
	// Calculate backoff: minBackoff * (2 ^ level)
	duration := minRecoveryBackoff
	for i := 0; i < level; i++ {
		duration *= time.Duration(backoffMultiplier)
		if duration >= maxBackoff {
			return maxBackoff
		}
	}

	// Cap at max backoff
	if duration > maxBackoff {
		duration = maxBackoff
	}

	return duration
}

// resetStabilityCount resets only the stability counter to 0 for a protocol.
// This is called when the dialer fails, restarting the recovery cycle while keeping
// the current backoff (penalty) level.
func (d *Dialer) resetStabilityCount(proto consts.L4ProtoStr) {
	protoIdx := d.protoIdx(proto)
	d.resetStabilityCountByIndex(protoIdx)
}

func (d *Dialer) resetStabilityCountForType(typ *NetworkType) {
	if typ == nil {
		return
	}
	d.resetStabilityCountByIndex(d.recoveryIdxForType(typ))
}

func (d *Dialer) resetStabilityCountByIndex(protoIdx int) {
	d.recoveryState[protoIdx].Lock()
	defer d.recoveryState[protoIdx].Unlock()

	d.recoveryState[protoIdx].stableSuccessCount = 0
}

const maxBackoffLevel = 6

func (d *Dialer) incrementBackoffLevel(proto consts.L4ProtoStr) {
	protoIdx := d.protoIdx(proto)
	d.incrementBackoffLevelByIndex(protoIdx)
}

func (d *Dialer) incrementBackoffLevelForType(typ *NetworkType) {
	if typ == nil {
		return
	}
	d.incrementBackoffLevelByIndex(d.recoveryIdxForType(typ))
}

func (d *Dialer) incrementBackoffLevelByIndex(protoIdx int) {
	// Deduplicate punishment in the same cycle (e.g., dual-stack IPv4/IPv6 both failing).
	// A 1-second cooldown using atomic swap ensures zero lock contention for hot-path failures.
	now := CachedTimeNano()
	if now-d.lastPunish[protoIdx].Swap(now) < int64(time.Second) {
		return
	}

	d.recoveryState[protoIdx].Lock()
	defer d.recoveryState[protoIdx].Unlock()

	if d.recoveryState[protoIdx].backoffLevel < maxBackoffLevel {
		d.recoveryState[protoIdx].backoffLevel++
	}
}

func (d *Dialer) GetBackoffLevel(proto consts.L4ProtoStr) int {
	protoIdx := d.protoIdx(proto)
	return d.getBackoffLevelByIndex(protoIdx)
}

func (d *Dialer) getBackoffLevelByIndex(protoIdx int) int {
	d.recoveryState[protoIdx].Lock()
	defer d.recoveryState[protoIdx].Unlock()
	return d.recoveryState[protoIdx].backoffLevel
}

// GetBackoffPenalty returns a latency penalty for nodes in recovery for a specific protocol.
// Penalty = current backoff duration / 20.
// This ensures recently recovered nodes are deprioritized until stable.
func (d *Dialer) GetBackoffPenalty(proto consts.L4ProtoStr) time.Duration {
	protoIdx := d.protoIdx(proto)
	return d.getBackoffPenaltyByIndex(protoIdx)
}

func (d *Dialer) getBackoffPenaltyForType(typ *NetworkType) time.Duration {
	if typ == nil {
		return 0
	}
	return d.getBackoffPenaltyByIndex(d.recoveryIdxForType(typ))
}

func (d *Dialer) getBackoffPenaltyByIndex(protoIdx int) time.Duration {
	d.recoveryState[protoIdx].Lock()
	defer d.recoveryState[protoIdx].Unlock()

	if d.recoveryState[protoIdx].backoffLevel == 0 {
		return 0
	}

	return d.calculateBackoffDurationLocked(d.recoveryState[protoIdx].backoffLevel, d.recoveryState[protoIdx].maxBackoff) / 20
}

// NotifyPeriodicCheckResult handles stability-based "wash white" logic for a protocol.
// Any failure resets the counter. A single success (with no failures) increments the stability counter.
func (d *Dialer) NotifyPeriodicCheckResult(proto consts.L4ProtoStr, success bool, failure bool) {
	protoIdx := d.protoIdx(proto)
	d.notifyPeriodicCheckResultByIndex(protoIdx, proto, success, failure)
}

func (d *Dialer) NotifyPeriodicCheckResultForType(typ *NetworkType, success bool, failure bool) {
	if typ == nil {
		return
	}
	d.notifyPeriodicCheckResultByIndex(d.recoveryIdxForType(typ), typ.L4Proto, success, failure)
}

func (d *Dialer) notifyPeriodicCheckResultByIndex(protoIdx int, proto consts.L4ProtoStr, success bool, failure bool) {
	if failure {
		d.resetStabilityCountByIndex(protoIdx)
		return
	}

	if success {
		d.recoveryState[protoIdx].Lock()
		defer d.recoveryState[protoIdx].Unlock()

		if d.recoveryState[protoIdx].backoffLevel == 0 {
			// Already clean.
			d.recoveryState[protoIdx].stableSuccessCount = 0
			return
		}

		d.recoveryState[protoIdx].stableSuccessCount++
		if d.recoveryState[protoIdx].stableSuccessCount >= 2 {
			d.recoveryState[protoIdx].stableSuccessCount = 0
			d.recoveryState[protoIdx].backoffLevel--

			d.Log.WithFields(logrus.Fields{
				"dialer":        d.Property().Name,
				"proto":         proto,
				"backoff_level": d.recoveryState[protoIdx].backoffLevel,
			}).Infoln("Recovery confirmed: long-term stability detected, backoff level decreased")
		}
	}
}

// markUnavailableFromProxyFailure immediately marks the dialer as unavailable.
// This is called when all proxy IPs have failed after retries, bypassing the health check cycle.
func (d *Dialer) markUnavailableFromProxyFailure() {
	d.Log.WithFields(logrus.Fields{
		"dialer": d.Property().Name,
	}).Warnln("Marking dialer as unavailable due to persistent proxy IP failures")

	// Use existing markUnavailable logic from connectivity_check.go.
	// Shared proxy transport failures must fan out into all transport domains.
	for _, networkType := range []*NetworkType{
		{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4},
		{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_6},
		{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, UdpHealthDomain: UdpHealthDomainDns, IsDns: true},
		{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_6, UdpHealthDomain: UdpHealthDomainDns, IsDns: true},
		{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, UdpHealthDomain: UdpHealthDomainData},
		{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_6, UdpHealthDomain: UdpHealthDomainData},
	} {
		d.ReportUnavailableForced(networkType, nil)
	}

	// Punishment: increment each recovery domain once.
	for _, recovery := range []struct {
		idx   int
		proto consts.L4ProtoStr
	}{
		{idx: idxTcp, proto: consts.L4ProtoStr_TCP},
		{idx: idxDnsUdp, proto: consts.L4ProtoStr_UDP},
		{idx: idxDataUdp, proto: consts.L4ProtoStr_UDP},
	} {
		d.incrementBackoffLevelByIndex(recovery.idx)
		d.resetStabilityCountByIndex(recovery.idx)
		d.cancelPendingRecoveryConfirmationByIndex(recovery.idx, recovery.proto)
	}
}

// isRecoveryTypeAlive returns true if any IP version of the specified health
// domain is currently alive.
func (d *Dialer) isRecoveryTypeAlive(networkType *NetworkType) bool {
	if networkType == nil {
		return false
	}
	v4 := &NetworkType{
		L4Proto:         networkType.L4Proto,
		IpVersion:       consts.IpVersionStr_4,
		IsDns:           networkType.IsDns,
		UdpHealthDomain: networkType.EffectiveUdpHealthDomain(),
	}
	v6 := &NetworkType{
		L4Proto:         networkType.L4Proto,
		IpVersion:       consts.IpVersionStr_6,
		IsDns:           networkType.IsDns,
		UdpHealthDomain: networkType.EffectiveUdpHealthDomain(),
	}
	return d.MustGetAlive(v4) || d.MustGetAlive(v6)
}

func (d *Dialer) GetHttpClient(idx int, ip netip.Addr, soMark uint32, mptcp bool) *http.Client {
	if d == nil {
		return nil
	}

	key := fmt.Sprintf("%d-%s", idx, ip.String())
	d.httpClientMu.Lock()
	defer d.httpClientMu.Unlock()

	if cli, ok := d.httpClients[key]; ok {
		return cli
	}

	cli := &http.Client{
		Transport: &http.Transport{
			DialContext: func(reqCtx context.Context, network, addr string) (c net.Conn, err error) {
				// Abort if the dialer is nil or its generation is already retired.
				if d == nil || d.ctx == nil || d.ctx.Err() != nil {
					return nil, context.Canceled
				}

				// Defensive check: ensure the underlying dialer implementation exists.
				// This prevents panics during rapid generation cleanup where some metadata
				// might persist even if the dialer pipeline is being torn down.
				if d.Dialer == nil {
					return nil, fmt.Errorf("dialer de-initialized")
				}

				// Combine request context with Dialer lifecycle context.
				// This ensures that when the Dialer is closed, all pending dials for health checks ARE ABORTED.
				// Connection reuse will happen naturally at the Transport level for the same host/IP.
				_, port, _ := net.SplitHostPort(addr)
				addr = net.JoinHostPort(ip.String(), port)

				conn, err := d.DialContext(reqCtx, common.MagicNetwork("tcp", soMark, mptcp), addr)
				if err != nil {
					return nil, err
				}
				return &netproxy.FakeNetConn{
					Conn:  conn,
					LAddr: nil,
					RAddr: nil,
				}, nil
			},
			// TLSHandshakeTimeout bounds the TLS setup phase so that a slow
			// or unresponsive proxy server does not indefinitely delay the
			// latency measurement for this probe target.
			TLSHandshakeTimeout: 10 * time.Second,
			// IdleConnTimeout and ResponseHeaderTimeout are per-connection knobs
			// that prevent resource leaks on idle or stalled connections.
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			// Allow a small pool of persistent connections per probe IP so that
			// repeated health checks reuse TCP connections instead of re-doing
			// the full TCP + TLS handshake each interval.
			MaxIdleConnsPerHost: 2,
			// Health checks send minimal HEAD/GET requests; disabling transparent
			// compression avoids the deflate/gzip overhead on the response path
			// and keeps latency measurements free from decompression noise.
			DisableCompression: true,
		},
	}
	d.httpClients[key] = cli
	return cli
}
