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
	"github.com/daeuniverse/dae/config"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"

	stickyip "github.com/daeuniverse/outbound/dialer/stickyip"
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
// In contrast, UDP DNS uses separate indices (IdxDnsUdp4/IdxDnsUdp6) because UDP has
// different transport characteristics and may have different connectivity results.
//
// Memory layout:
//   - [0] IdxDnsTcp4 -> aliases to [4] IdxTcp4
//   - [1] IdxDnsTcp6 -> aliases to [5] IdxTcp6
//   - [2] IdxDnsUdp4 -> independent UDP DNS IPv4 check
//   - [3] IdxDnsUdp6 -> independent UDP DNS IPv6 check
//   - [4] IdxTcp4    -> TCP IPv4 check (shared with TCP DNS)
//   - [5] IdxTcp6    -> TCP IPv6 check (shared with TCP DNS)
const (
	IdxDnsTcp4 = 0
	IdxDnsTcp6 = 1
	IdxDnsUdp4 = 2
	IdxDnsUdp6 = 3
	IdxTcp4    = 4
	IdxTcp6    = 5

	idxTcp = 0
	idxUdp = 1
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
	collections      [6]*collection

	tickerMu   sync.Mutex
	ticker     *time.Timer
	checkCh    chan time.Time
	checkUdpCh chan struct{} // trigger resuscitation for all UDP collections (IPv4+v6)
	checkTcpCh chan struct{} // trigger resuscitation for all TCP collections (IPv4+v6)
	ctx        context.Context
	cancel     context.CancelFunc

	checkActivated bool

	httpClients  map[string]*http.Client
	httpClientMu sync.Mutex

	failCount        [6]int
	trafficFailCount [6]atomic.Int32

	// stickyIpDialer holds reference to the sticky IP wrapper for cache management
	// This is used for health check cycle management and failover tracking
	stickyIpDialer *stickyip.StickyIpDialer

	// recoveryState manages exponential backoff for recovery detection
	// This prevents flapping when a dialer recovers but might fail again soon.
	// Index 0: TCP, Index 1: UDP.
	recoveryState [2]struct {
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
	}
	lastNotifyUdp atomic.Int64
	lastNotifyTcp atomic.Int64
}

// recoveryBackoffLevelStore provides persistent backoff level storage
// This allows recovery state to survive Clone() operations and reloads
// Key: Dialer name, Value: [TCP level, UDP level]
type recoveryBackoffLevelStore struct {
	sync.RWMutex
	levels map[string][2]int
}

var globalRecoveryBackoffLevelStore = &recoveryBackoffLevelStore{
	levels: make(map[string][2]int),
}

// Get returns the backoff level for the given dialer name and protocol index.
// Returns 0 if the dialer name or protocol is not found.
func (s *recoveryBackoffLevelStore) Get(dialerName string) [2]int {
	s.RLock()
	defer s.RUnlock()
	if level, ok := s.levels[dialerName]; ok {
		return level
	}
	return [2]int{0, 0}
}

// Set updates the backoff level for the given dialer name and protocol index.
func (s *recoveryBackoffLevelStore) Set(dialerName string, protoIdx int, level int) {
	s.Lock()
	defer s.Unlock()
	l := s.levels[dialerName]
	l[protoIdx] = level
	s.levels[dialerName] = l
}

// Delete removes the backoff level for the given dialer name.
// This can be used when a dialer is permanently removed.
func (s *recoveryBackoffLevelStore) Delete(dialerName string) {
	s.Lock()
	defer s.Unlock()
	delete(s.levels, dialerName)
}

type GlobalOption struct {
	D.ExtraOption
	Log               *logrus.Logger
	TcpCheckOptionRaw TcpCheckOptionRaw // Lazy parse
	CheckDnsOptionRaw CheckDnsOptionRaw // Lazy parse
	CheckInterval     time.Duration
	CheckTolerance    time.Duration
	CheckDnsTcp       bool
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
		TcpCheckOptionRaw: TcpCheckOptionRaw{Raw: global.TcpCheckUrl, Log: log, ResolverNetwork: common.MagicNetwork("udp", global.SoMarkFromDae, global.Mptcp), Method: global.TcpCheckHttpMethod},
		CheckDnsOptionRaw: CheckDnsOptionRaw{Raw: global.UdpCheckDns, ResolverNetwork: common.MagicNetwork("udp", global.SoMarkFromDae, global.Mptcp), Somark: global.SoMarkFromDae},
		CheckInterval:     global.CheckInterval,
		CheckTolerance:    global.CheckTolerance,
		CheckDnsTcp:       true,
	}
}

// NewDialer is for register in general.
func NewDialer(dialer netproxy.Dialer, option *GlobalOption, iOption InstanceOption, property *Property) *Dialer {
	var collections [6]*collection
	for _, i := range []int{IdxDnsUdp4, IdxDnsUdp6, IdxTcp4, IdxTcp6} {
		collections[i] = newCollection()
	}
	collections[IdxDnsTcp4] = collections[IdxTcp4]
	collections[IdxDnsTcp6] = collections[IdxTcp6]

	ctx, cancel := context.WithCancel(context.Background())
	d := &Dialer{
		GlobalOption:     option,
		InstanceOption:   iOption,
		property:         property,
		collectionFineMu: sync.RWMutex{},
		collections:      collections,
		tickerMu:         sync.Mutex{},
		ticker:           nil,
		checkCh:          make(chan time.Time, 1),
		checkUdpCh:       make(chan struct{}, 1),
		checkTcpCh:       make(chan struct{}, 1),
		ctx:              ctx,
		cancel:           cancel,
		httpClients:      make(map[string]*http.Client),
	}
	d.Dialer = dialer

	// Initialize recovery detection with adjusted max backoff
	d.initRecoveryDetection(option.CheckInterval)

	// Restore backoff level from persistent store (for Clone() and reload scenarios)
	// This maintains recovery progression across dialer recreations
	if d.property != nil {
		if dialerName := d.Property().Name; dialerName != "" {
			levels := globalRecoveryBackoffLevelStore.Get(dialerName)
			d.recoveryState[idxTcp].backoffLevel = levels[idxTcp]
			d.recoveryState[idxUdp].backoffLevel = levels[idxUdp]
		}
	}

	option.Log.WithField("dialer", d.Property().Name).
		WithField("p", unsafe.Pointer(d)).
		Traceln("NewDialer")
	return d
}

func (d *Dialer) Clone() *Dialer {
	return NewDialer(d.Dialer, d.GlobalOption, d.InstanceOption, d.property)
}

func (d *Dialer) Close() error {
	d.cancel()

	// Cancel any pending recovery confirmation to prevent timer leaks
	d.cancelPendingRecoveryConfirmation(consts.L4ProtoStr_TCP)
	d.cancelPendingRecoveryConfirmation(consts.L4ProtoStr_UDP)

	d.tickerMu.Lock()
	if d.ticker != nil {
		d.ticker.Stop()
	}
	d.tickerMu.Unlock()

	d.httpClientMu.Lock()
	for k, cli := range d.httpClients {
		if cli != nil {
			if t, ok := cli.Transport.(*http.Transport); ok {
				t.CloseIdleConnections()
			}
			delete(d.httpClients, k)
		}
	}
	d.httpClientMu.Unlock()
	return nil
}

func (d *Dialer) Property() *Property {
	return d.property
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

		// Trigger recovery detection with exponential backoff ONLY on revival
		if isRevival {
			d.triggerRecoveryDetection(typ)
		}
	} else {
		// Reset stability counter on any failure (Trust Level Reset)
		d.resetStabilityCount(typ.L4Proto)

		// Cancel any pending recovery confirmation to prevent premature recovery
		// if the node revives again before the original timer fires.
		d.cancelPendingRecoveryConfirmation(typ.L4Proto)

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

func (d *Dialer) protoIdx(proto consts.L4ProtoStr) int {
	if proto == consts.L4ProtoStr_UDP {
		return idxUdp
	}
	return idxTcp
}

// NotifyProxyFailure is called when a proxy server connection fails (e.g., connection refused).
// It immediately invalidates the cached IP for the specified protocol so that
// the next connection can try a different IP.
func (d *Dialer) NotifyProxyFailure(proxyAddr, protocol string) {
	if d.stickyIpDialer == nil {
		return
	}
	// Invalidate the cache for this specific protocol
	d.stickyIpDialer.InvalidateProtocolCache(proxyAddr, protocol)
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

	for i := 0; i < 2; i++ {
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

	protoIdx := d.protoIdx(target.L4Proto)
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
	d.recoveryState[protoIdx].pendingNetworkType = networkType
	d.recoveryState[protoIdx].confirmTimer = time.AfterFunc(backoff, func() {
		d.confirmRecovery(networkType)
	})
}

// confirmRecovery confirms recovery after backoff period.
// It checks if the dialer is still healthy before confirming.
func (d *Dialer) confirmRecovery(networkType *NetworkType) {
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

	protoIdx := d.protoIdx(networkType.L4Proto)
	d.recoveryState[protoIdx].Lock()
	// Clear timer
	if d.recoveryState[protoIdx].confirmTimer != nil {
		d.recoveryState[protoIdx].confirmTimer = nil
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
	alive := d.MustGetAlive(networkType)
	if !alive {
		d.recoveryState[protoIdx].Unlock()
		d.Log.WithFields(logrus.Fields{
			"dialer":  d.Property().Name,
			"network": networkType.String(),
		}).Debugln("Recovery confirmation failed: still unhealthy, will retry on next health check")
		return
	}

	// Confirm recovery - increase backoff level for next time
	// Only increment if level hasn't been reset by a concurrent failure
	if d.recoveryState[protoIdx].backoffLevel == currentBackoffLevel {
		d.recoveryState[protoIdx].backoffLevel++
		// Persist the incremented backoff level to survive Clone() and reloads
		if d.property != nil {
			if dialerName := d.Property().Name; dialerName != "" {
				globalRecoveryBackoffLevelStore.Set(dialerName, protoIdx, d.recoveryState[protoIdx].backoffLevel)
			}
		}
		d.Log.WithFields(logrus.Fields{
			"dialer":        d.Property().Name,
			"proto":         networkType.L4Proto,
			"network":       networkType.String(),
			"backoff_level": d.recoveryState[protoIdx].backoffLevel,
		}).Infoln("Recovery confirmed after exponential backoff")
	} else {
		// Level was reset by concurrent failure, don't increment
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
	d.recoveryState[protoIdx].Lock()
	defer d.recoveryState[protoIdx].Unlock()

	if d.recoveryState[protoIdx].confirmTimer != nil {
		d.recoveryState[protoIdx].confirmTimer.Stop()
		d.recoveryState[protoIdx].confirmTimer = nil

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

// fullResetBackoffState resets both backoff level and stability counter to 0.
// This is used for manual resets or major configuration changes.
func (d *Dialer) fullResetBackoffState(proto consts.L4ProtoStr) {
	protoIdx := d.protoIdx(proto)
	d.recoveryState[protoIdx].Lock()
	defer d.recoveryState[protoIdx].Unlock()

	d.recoveryState[protoIdx].backoffLevel = 0
	d.recoveryState[protoIdx].stableSuccessCount = 0

	// Also update persistent store
	if d.property != nil {
		if dialerName := d.Property().Name; dialerName != "" {
			globalRecoveryBackoffLevelStore.Set(dialerName, protoIdx, 0)
		}
	}
}

// resetStabilityCount resets only the stability counter to 0 for a protocol.
// This is called when the dialer fails, restarting the recovery cycle while keeping
// the current backoff (penalty) level.
func (d *Dialer) resetStabilityCount(proto consts.L4ProtoStr) {
	protoIdx := d.protoIdx(proto)
	d.recoveryState[protoIdx].Lock()
	defer d.recoveryState[protoIdx].Unlock()

	d.recoveryState[protoIdx].stableSuccessCount = 0
}

func (d *Dialer) GetBackoffLevel(proto consts.L4ProtoStr) int {
	protoIdx := d.protoIdx(proto)
	d.recoveryState[protoIdx].Lock()
	defer d.recoveryState[protoIdx].Unlock()
	return d.recoveryState[protoIdx].backoffLevel
}

// GetBackoffPenalty returns a latency penalty for nodes in recovery for a specific protocol.
// Penalty = current backoff duration / 20.
// This ensures recently recovered nodes are deprioritized until stable.
func (d *Dialer) GetBackoffPenalty(proto consts.L4ProtoStr) time.Duration {
	protoIdx := d.protoIdx(proto)
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
	if failure {
		d.resetStabilityCount(proto)
		return
	}

	if success {
		protoIdx := d.protoIdx(proto)
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

			// Persist the decremented backoff level
			if d.property != nil {
				if dialerName := d.Property().Name; dialerName != "" {
					globalRecoveryBackoffLevelStore.Set(dialerName, protoIdx, d.recoveryState[protoIdx].backoffLevel)
				}
			}

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

	// Use existing markUnavailable logic from connectivity_check.go
	// This will update collection.Alive and notify AliveDialerSet
	// Mark both TCP and UDP across all supported IP versions as dead since they
	// share the same proxy IP/health. Bypass threshold to ensure immediate failover.
	protocols := []consts.L4ProtoStr{consts.L4ProtoStr_TCP, consts.L4ProtoStr_UDP}
	ipVersions := []consts.IpVersionStr{consts.IpVersionStr_4, consts.IpVersionStr_6}

	for _, proto := range protocols {
		for _, ipVersion := range ipVersions {
			networkType := &NetworkType{
				L4Proto:   proto,
				IpVersion: ipVersion,
				IsDns:     false,
			}
			d.ReportUnavailableForced(networkType, nil)
		}
	}

	// Reset stability count (Trust Level)
	d.resetStabilityCount(consts.L4ProtoStr_TCP)
	d.resetStabilityCount(consts.L4ProtoStr_UDP)

	// Cancel any pending recovery confirmation
	d.cancelPendingRecoveryConfirmation(consts.L4ProtoStr_TCP)
	d.cancelPendingRecoveryConfirmation(consts.L4ProtoStr_UDP)
}

func (d *Dialer) GetHttpClient(idx int, ip netip.Addr, soMark uint32, mptcp bool) *http.Client {
	key := fmt.Sprintf("%d-%s", idx, ip.String())

	d.httpClientMu.Lock()
	defer d.httpClientMu.Unlock()

	if cli, ok := d.httpClients[key]; ok {
		return cli
	}

	cli := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (c net.Conn, err error) {
				// Use the specific IP resolved for this probe to ensure accurate measurement.
				// Connection reuse will happen naturally at the Transport level for the same host/IP.
				_, port, _ := net.SplitHostPort(addr)
				addr = net.JoinHostPort(ip.String(), port)

				conn, err := d.DialContext(ctx, common.MagicNetwork("tcp", soMark, mptcp), addr)
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
