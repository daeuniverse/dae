/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/okzk/sdnotify"
	"github.com/sirupsen/logrus"
)

type reloadManager struct {
	reloadReqs                   chan reloadRequest
	runStateChanges              chan struct{}
	sigs                         <-chan os.Signal
	reloading                    atomic.Bool
	reloadActive                 atomic.Bool
	reloadPending                atomic.Bool
	mu                           sync.Mutex
	reloadingErr                 error
	lastRetirementMu             sync.Mutex
	lastRetirementCancel         context.CancelFunc
	pendingStagedHandoff         *stagedReloadHandoff
	pendingRetirementDone        <-chan struct{}
	pendingReloadRequestedAt     time.Time
	pendingReloadRequestedAtMono uint64
	transitionMu                 sync.Mutex
	transitionCond               *sync.Cond
	transitionActive             bool
	shutdownStarted              bool
	activeRetirement             *activeRetirementTask
}

// activeRetirementTask transfers cleanup ownership of one published
// generation to the retirement worker. The generation identity is required
// when a canceled worker completes after a newer reload has started.
type activeRetirementTask struct {
	generation *runtimeGeneration
	cancel     context.CancelFunc
	done       chan struct{}
}

func newReloadManager(reloadReqs chan reloadRequest, runStateChanges chan struct{}, sigs <-chan os.Signal) *reloadManager {
	m := &reloadManager{
		reloadReqs:      reloadReqs,
		runStateChanges: runStateChanges,
		sigs:            sigs,
	}
	m.transitionCond = sync.NewCond(&m.transitionMu)
	return m
}

func (m *reloadManager) queueReloadRequest(log *logrus.Logger, req reloadRequest) {
	tryQueueReloadRequest(log, m.reloadReqs, &m.reloadActive, &m.reloadPending, req)
}

func (m *reloadManager) beginHandoff() {
	beginReloadHandoff(&m.reloading, m.runStateChanges)
}

func (m *reloadManager) setReloadError(err error) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.reloadingErr = err
	m.mu.Unlock()
}

func (m *reloadManager) reloadError() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reloadingErr
}

func (m *reloadManager) coalesceReloadRequest(req reloadRequest) reloadRequest {
	reloadStartedAt := req.requestedAt
	if reloadStartedAt.IsZero() {
		reloadStartedAt = time.Now()
	}
	req.requestedAt = reloadStartedAt
coalesce:
	for {
		select {
		case nextReq := <-m.reloadReqs:
			req = nextReq
			if req.requestedAt.IsZero() {
				req.requestedAt = time.Now()
			}
			continue
		default:
			break coalesce
		}
	}
	return req
}

func (m *reloadManager) setPendingStagedHandoff(handoff *stagedReloadHandoff, requestedAt time.Time, requestedAtMono uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pendingStagedHandoff = handoff
	m.pendingReloadRequestedAt = requestedAt
	m.pendingReloadRequestedAtMono = requestedAtMono
}

func (m *reloadManager) clearPendingStagedHandoff() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.pendingStagedHandoff = nil
	m.mu.Unlock()
}

func (m *reloadManager) currentPendingStagedHandoff() *stagedReloadHandoff {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pendingStagedHandoff
}

func (m *reloadManager) setPendingReloadMetadata(requestedAt time.Time, requestedAtMono uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.pendingReloadRequestedAt = requestedAt
	m.pendingReloadRequestedAtMono = requestedAtMono
	m.mu.Unlock()
}

func (m *reloadManager) clearPendingRetirement() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.pendingRetirementDone = nil
	m.mu.Unlock()
}

func (m *reloadManager) takePendingRetirementDone() <-chan struct{} {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	done := m.pendingRetirementDone
	m.pendingRetirementDone = nil
	return done
}

func (m *reloadManager) buildShutdownHandoff() *signalShutdownStagedHandoff {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pendingStagedHandoff == nil {
		return nil
	}
	return &signalShutdownStagedHandoff{
		oldListener:     m.pendingStagedHandoff.oldListener,
		oldControlPlane: m.pendingStagedHandoff.oldControlPlane,
		oldCancel:       m.pendingStagedHandoff.oldCancel,
		newListener:     m.pendingStagedHandoff.newListener,
		newControlPlane: m.pendingStagedHandoff.newControlPlane,
		newCancel:       m.pendingStagedHandoff.newCancel,
	}
}

func (m *reloadManager) pendingDNSHandoffActive(current *control.ControlPlane) bool {
	if m == nil {
		return false
	}
	handoff := m.currentPendingStagedHandoff()
	return handoff != nil &&
		!handoff.freshDatapath &&
		handoff.oldControlPlane != nil &&
		handoff.oldControlPlane.SharesActiveDnsControllerWith(current)
}

type preparedDNSHandoffHookCallbacks struct {
	reuseController func() bool
	reuseListener   func() bool
	stopOldListener func() error
}

type preparedDNSHandoffHooks struct {
	reuseHook func() error
	startHook func() error
}

func buildPreparedDNSHandoffHooks(log *logrus.Logger, enableReuse bool, callbacks preparedDNSHandoffHookCallbacks) preparedDNSHandoffHooks {
	var hooks preparedDNSHandoffHooks
	if enableReuse {
		hooks.reuseHook = func() error {
			if callbacks.reuseController == nil || !callbacks.reuseController() {
				return fmt.Errorf("reuse DNS controller for prepared handoff")
			}
			if callbacks.reuseListener != nil && callbacks.reuseListener() {
				return nil
			}
			return nil
		}
	}
	hooks.startHook = func() error {
		if callbacks.reuseListener != nil && callbacks.reuseListener() {
			return nil
		}
		if callbacks.stopOldListener == nil {
			return nil
		}
		if err := callbacks.stopOldListener(); err != nil {
			if log != nil {
				log.WithError(err).Warnln("[Reload] Failed to stop previous DNS listener before staged cutover")
			}
			return err
		}
		return nil
	}
	return hooks
}

func (m *reloadManager) installPreparedDNSHandoffHooks(log *logrus.Logger, current *control.ControlPlane, conf *config.Config) {
	if m == nil || current == nil || conf == nil {
		return
	}
	handoff := m.currentPendingStagedHandoff()
	if handoff == nil || handoff.freshDatapath {
		return
	}
	hooks := buildPreparedDNSHandoffHooks(log, dnsConfigEqual(handoff.oldConf, conf), preparedDNSHandoffHookCallbacks{
		reuseController: func() bool {
			reused := current.ReuseDNSControllerFrom(handoff.oldControlPlane)
			handoff.dnsControllerMoved = reused
			return reused
		},
		reuseListener: func() bool {
			reused := current.ReuseDNSListenerFrom(handoff.oldControlPlane)
			handoff.dnsListenerMoved = reused
			return reused
		},
		stopOldListener: handoff.oldControlPlane.StopDNSListener,
	})
	if hooks.reuseHook != nil {
		current.SetPreparedDNSReuseHook(hooks.reuseHook)
	}
	current.SetPreparedDNSStartHook(hooks.startHook)
}

func (m *reloadManager) finishReloadFailure() {
	m.reloading.Store(false)
	m.reloadActive.Store(false)
	clearReloadPending(&m.reloadPending)
}

// failPublishedReloadAttempt reports a recoverable post-handoff failure to
// the service manager and progress file, then clears the same busy flags as
// finishReloadFailure. Unlike failReloadAttempt, reloading is already true
// (beginHandoff ran) so it must be cleared here.
func (m *reloadManager) failPublishedReloadAttempt(reloadErr error) {
	if reloadErr != nil {
		_ = sdnotify.Ready()
		_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
	}
	m.finishReloadFailure()
}

// failReloadAttempt reports a failed reload attempt to the service manager
// and the progress file, then clears the busy/pending bookkeeping so the
// live generation keeps serving and the next reload request is accepted.
func (m *reloadManager) failReloadAttempt(reloadErr error) {
	if reloadErr != nil {
		_ = sdnotify.Ready()
		_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
	}
	m.reloadActive.Store(false)
	clearReloadPending(&m.reloadPending)
}

func (m *reloadManager) finishReloadSuccess() {
	m.reloading.Store(false)
	m.reloadActive.Store(false)
	releaseReloadPendingAfterRetirement(&m.reloadPending, m.takePendingRetirementDone())
}

// beginReloadTransition reserves the cutover critical section. Shutdown uses
// the same barrier so it cannot transfer generation ownership while a reload
// is between datapath preparation and publication.
func (m *reloadManager) beginReloadTransition() bool {
	if m == nil {
		return false
	}
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()
	if m.shutdownStarted || m.transitionActive {
		return false
	}
	m.transitionActive = true
	return true
}

func (m *reloadManager) endReloadTransition() {
	if m == nil {
		return
	}
	m.transitionMu.Lock()
	if m.transitionActive {
		m.transitionActive = false
		m.transitionCond.Broadcast()
	}
	m.transitionMu.Unlock()
}

// shutdownSupervisor freezes new reload transitions, joins the current
// retirement worker, and then atomically transfers any remaining generation
// ownership to the shutdown caller.
func (m *reloadManager) shutdownSupervisor(supervisor *runtimeSupervisor) runtimeSupervisorSnapshot {
	if m == nil {
		if supervisor == nil {
			return runtimeSupervisorSnapshot{}
		}
		return supervisor.shutdown()
	}
	m.transitionMu.Lock()
	m.shutdownStarted = true
	for m.transitionActive {
		m.transitionCond.Wait()
	}
	m.transitionMu.Unlock()

	m.lastRetirementMu.Lock()
	task := m.activeRetirement
	if task != nil && task.cancel != nil {
		task.cancel()
	}
	m.lastRetirementMu.Unlock()
	if task != nil {
		<-task.done
		if supervisor != nil {
			// A shutdown-owned worker may be joined after its completion
			// notification but before it releases supervisor retirement state.
			// The generation identity makes this cleanup idempotent.
			supervisor.markRetirementComplete(task.generation)
		}
	}
	if supervisor == nil {
		return runtimeSupervisorSnapshot{}
	}
	return supervisor.shutdown()
}

func (m *reloadManager) buildShutdownHandoffWithSupervisor(snapshot runtimeSupervisorSnapshot, current *runtimeGeneration) *signalShutdownStagedHandoff {
	if m == nil {
		return nil
	}
	var handoff signalShutdownStagedHandoff
	if snapshot.retiring != nil {
		handoff.oldListener = snapshot.retiring.listener
		handoff.oldControlPlane = snapshot.retiring.controlPlane
		handoff.oldCancel = snapshot.retiring.cancel
	}
	if snapshot.prepared != nil {
		handoff.newListener = snapshot.prepared.listener
		handoff.newControlPlane = snapshot.prepared.controlPlane
		handoff.newCancel = snapshot.prepared.cancel
	}
	if snapshot.active != nil && snapshot.active != current && handoff.newControlPlane == nil {
		handoff.newListener = snapshot.active.listener
		handoff.newControlPlane = snapshot.active.controlPlane
		handoff.newCancel = snapshot.active.cancel
	}
	if handoff.oldListener == nil && handoff.oldControlPlane == nil && handoff.oldCancel == nil && handoff.newListener == nil && handoff.newControlPlane == nil && handoff.newCancel == nil {
		return nil
	}
	return &handoff
}

func (m *reloadManager) startControlPlaneRetirement(
	log *logrus.Logger,
	oldControlPlane *control.ControlPlane,
	successor *control.ControlPlane,
	oldCancel context.CancelFunc,
	abortConnections bool,
	supervisor *runtimeSupervisor,
	retiringGeneration *runtimeGeneration,
) {
	if m == nil || oldControlPlane == nil {
		return
	}
	if supervisor == nil || retiringGeneration == nil || !supervisor.ownsRetiring(retiringGeneration) {
		return
	}
	m.lastRetirementMu.Lock()
	if m.lastRetirementCancel != nil {
		m.lastRetirementCancel()
	}
	retireCtx, retireCancel := context.WithCancel(context.Background())
	m.lastRetirementCancel = retireCancel
	retirementDone := make(chan struct{})
	task := &activeRetirementTask{
		generation: retiringGeneration,
		cancel:     retireCancel,
		done:       retirementDone,
	}
	m.activeRetirement = task
	m.lastRetirementMu.Unlock()

	if log != nil {
		log.Infoln("[Reload] Retiring old control plane")
	}
	// lastRetirementMu only serializes cancellation/replacement of the previous
	// retirement goroutine. The timing metadata below belongs to the reload
	// manager state itself, so it is read under m.mu instead. This split is safe
	// because reload requests are handled by a single worker goroutine.
	m.mu.Lock()
	m.pendingRetirementDone = retirementDone
	drainBudget := remainingReloadRetirementBudget(m.pendingReloadRequestedAt, reloadTotalSwitchBudget)
	staleBeforeNs := m.pendingReloadRequestedAtMono
	m.mu.Unlock()

	go func(task *activeRetirementTask) {
		defer close(task.done)
		defer func() {
			m.lastRetirementMu.Lock()
			if m.activeRetirement == task {
				m.activeRetirement = nil
				m.lastRetirementCancel = nil
			}
			m.lastRetirementMu.Unlock()
		}()

		oldControlPlane.MarkRetired()
		retireControlPlaneConnections(log, retireCtx, oldControlPlane, abortConnections, drainBudget)

		if oldCancel != nil {
			oldCancel()
		}
		if closeErr := oldControlPlane.Close(); closeErr != nil && log != nil {
			log.WithError(closeErr).Warnln("[Reload] Old control plane close did not finish cleanly")
		}
		if successor != nil {
			successor.RunReloadRetirementCleanup(staleBeforeNs)
		}
		supervisor.markRetirementComplete(task.generation)
		if log != nil {
			log.Infoln("[Reload] Retired old control plane")
		}
	}(task)
}

func (m *reloadManager) refreshPprofServer(server **http.Server, port uint16) {
	if server == nil {
		return
	}
	if *server != nil {
		pprofCtx, pprofCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = (*server).Shutdown(pprofCtx)
		pprofCancel()
		*server = nil
	}
	if port != 0 {
		pprofAddr := "localhost:" + strconv.Itoa(int(port))
		*server = &http.Server{Addr: pprofAddr, Handler: nil}
		go func() { _ = (*server).ListenAndServe() }()
	}
}

func dnsConfigEqual(oldConf *config.Config, newConf *config.Config) bool {
	if oldConf == nil || newConf == nil {
		return false
	}
	return dnsConfigFingerprint(oldConf.Dns) == dnsConfigFingerprint(newConf.Dns)
}

// bpfDatapathChanged returns true only when a config diff changes kernel
// datapath inputs that cannot be applied via the staged-hot-handoff path —
// namely BPF program constants (so_mark), TC hook attach points (interfaces),
// or map dimensions (conn_state_map_size). These require a fresh BPF object
// load while reusing the process-owned flow-state maps.
//
// Policy-level changes — routing rules, fallback, outbound groups, and DNS
// routing — do NOT require a BPF reload: they are delivered via BPF map
// updates (routing_map, domain_routing_map) and Go-side dialer rebuilds.
// The staged-hot-handoff path handles them seamlessly through
// CommitPreparedDatapath, which atomically applies the new routing_map,
// clears+replays domain_routing_map, and flips TC hooks while established
// connections remain owned by the process-level session manager.
func bpfDatapathChanged(oldConf, newConf *config.Config) bool {
	if oldConf == nil || newConf == nil {
		return true
	}
	// Interface changes require TC hook re-attachment to different devices.
	if !reflect.DeepEqual(oldConf.Global.LanInterface, newConf.Global.LanInterface) {
		return true
	}
	if !reflect.DeepEqual(oldConf.Global.WanInterface, newConf.Global.WanInterface) {
		return true
	}
	// Map dimensions are fixed at BPF load time.
	if oldConf.Global.BpfConnStateMapSize != newConf.Global.BpfConnStateMapSize {
		return true
	}
	// so_mark_from_dae is a BPF program constant (set via spec.Variables).
	if oldConf.Global.SoMarkFromDae != newConf.Global.SoMarkFromDae ||
		oldConf.Global.SoMarkFromDaeSet != newConf.Global.SoMarkFromDaeSet {
		return true
	}
	return false
}

func preserveReloadInterfaceBindings(oldConf, newConf *config.Config) []string {
	if oldConf == nil || newConf == nil {
		return nil
	}
	lan := append([]string(nil), newConf.Global.LanInterface...)
	wan := append([]string(nil), newConf.Global.WanInterface...)
	remove := func(values []string, target string) []string {
		result := values[:0]
		for _, value := range values {
			if value != target {
				result = append(result, value)
			}
		}
		return result
	}

	var deferred []string
	oldLAN := make(map[string]struct{}, len(oldConf.Global.LanInterface))
	for _, iface := range oldConf.Global.LanInterface {
		oldLAN[iface] = struct{}{}
		changed := !slices.Contains(lan, iface) || slices.Contains(wan, iface)
		wan = remove(wan, iface)
		if !slices.Contains(lan, iface) {
			lan = append(lan, iface)
		}
		if changed {
			deferred = append(deferred, "lan:"+iface)
		}
	}
	for _, iface := range oldConf.Global.WanInterface {
		if _, isLAN := oldLAN[iface]; isLAN {
			continue
		}
		changed := !slices.Contains(wan, iface) || slices.Contains(lan, iface)
		lan = remove(lan, iface)
		if !slices.Contains(wan, iface) {
			wan = append(wan, iface)
		}
		if changed {
			deferred = append(deferred, "wan:"+iface)
		}
	}
	newConf.Global.LanInterface = lan
	newConf.Global.WanInterface = wan
	return deferred
}

// dnsConfigFingerprint captures only the DNS fields that affect BPF datapath
// state (domain_routing_map, routing rules, upstream resolution). Runtime-tunable
// parameters (OptimisticCache, OptimisticCacheTtl, MaxCacheSize) are intentionally
// excluded because they are atomic-tunable via DnsController.UpdateRuntime and do
// not require BPF map changes. Including them would cause unnecessary
// domain_routing_map clear+replay during staged handoff, creating a race window
// where the old control plane loses domain routing (see dae#1013).
//
// Must be kept in sync with config.Dns routing-affecting fields.
// TestDNSConfigFingerprintCoversAllDnsFields guards the contract.
func dnsConfigFingerprint(dns config.Dns) string {
	var b strings.Builder
	writeKeyableStrings := func(name string, values []config.KeyableString) {
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(strconv.Itoa(len(values)))
		for _, value := range values {
			b.WriteByte(':')
			b.WriteString(strconv.Quote(string(value)))
		}
		b.WriteByte(';')
	}
	writeFunction := func(f *config_parser.Function) {
		if f == nil {
			b.WriteString("<nil>")
			return
		}
		// MarshalString (not String): the display form ellipsizes params from
		// index 5 on, so a DNS rule function with six or more params would
		// fingerprint identical to a different one and the reload would skip
		// the domain_routing_map clear+replay, leaving the new rule inactive.
		b.WriteString(f.MarshalString(true, false, true))
	}
	writeFunctionOrString := func(name string, value config.FunctionOrString) {
		b.WriteString(name)
		b.WriteByte('=')
		switch value := value.(type) {
		case string:
			b.WriteString("string:")
			b.WriteString(strconv.Quote(value))
		case *config_parser.Function:
			b.WriteString("function:")
			writeFunction(value)
		case []*config_parser.Function:
			b.WriteString("functions:")
			b.WriteString(strconv.Itoa(len(value)))
			for _, f := range value {
				b.WriteByte(':')
				writeFunction(f)
			}
		default:
			b.WriteString("unsupported:")
			fmt.Fprintf(&b, "%T", value)
		}
		b.WriteByte(';')
	}
	writeRules := func(name string, rules []*config_parser.RoutingRule) {
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(strconv.Itoa(len(rules)))
		for _, rule := range rules {
			b.WriteByte(':')
			if rule == nil {
				b.WriteString("<nil>")
				continue
			}
			b.WriteString(rule.String(false, true, true))
		}
		b.WriteByte(';')
	}
	writeRouting := func(name string, routing config.DnsRouting) {
		b.WriteString(name)
		b.WriteByte('{')
		writeRules("request.rules", routing.Request.Rules)
		writeFunctionOrString("request.fallback", routing.Request.Fallback)
		writeRules("response.rules", routing.Response.Rules)
		writeFunctionOrString("response.fallback", routing.Response.Fallback)
		b.WriteByte('}')
	}

	b.WriteString("ipversion_prefer=")
	b.WriteString(strconv.Itoa(dns.IpVersionPrefer))
	b.WriteByte(';')
	writeKeyableStrings("fixed_domain_ttl", dns.FixedDomainTtl)
	writeKeyableStrings("upstream", dns.Upstream)
	writeRouting("routing", dns.Routing)
	b.WriteString("bind=")
	b.WriteString(strconv.Quote(dns.Bind))
	b.WriteByte(';')
	return b.String()
}
