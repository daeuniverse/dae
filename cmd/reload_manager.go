/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/config_parser"
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
}

func newReloadManager(reloadReqs chan reloadRequest, runStateChanges chan struct{}, sigs <-chan os.Signal) *reloadManager {
	return &reloadManager{
		reloadReqs:      reloadReqs,
		runStateChanges: runStateChanges,
		sigs:            sigs,
	}
}

func (m *reloadManager) queueReloadRequest(log *logrus.Logger, req reloadRequest) bool {
	return tryQueueReloadRequest(log, m.reloadReqs, &m.reloadActive, &m.reloadPending, req)
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
		newListener:     m.pendingStagedHandoff.newListener,
		newControlPlane: m.pendingStagedHandoff.newControlPlane,
	}
}

func (m *reloadManager) pendingDNSHandoffActive(current *control.ControlPlane) bool {
	if m == nil {
		return false
	}
	handoff := m.currentPendingStagedHandoff()
	return handoff != nil &&
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
			if callbacks.reuseController != nil {
				_ = callbacks.reuseController()
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
	if handoff == nil {
		return
	}
	hooks := buildPreparedDNSHandoffHooks(log, dnsConfigEqual(handoff.oldConf, conf), preparedDNSHandoffHookCallbacks{
		reuseController: func() bool {
			return current.ReuseDNSControllerFrom(handoff.oldControlPlane)
		},
		reuseListener: func() bool {
			return current.ReuseDNSListenerFrom(handoff.oldControlPlane)
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

func (m *reloadManager) finishReloadSuccess() {
	m.reloading.Store(false)
	m.reloadActive.Store(false)
	releaseReloadPendingAfterRetirement(&m.reloadPending, m.takePendingRetirementDone())
}

func (m *reloadManager) startControlPlaneRetirement(
	log *logrus.Logger,
	oldControlPlane *control.ControlPlane,
	successor *control.ControlPlane,
	oldCancel context.CancelFunc,
	abortConnections bool,
	hasOverlap bool,
) {
	if m == nil || oldControlPlane == nil {
		return
	}
	m.lastRetirementMu.Lock()
	if m.lastRetirementCancel != nil {
		m.lastRetirementCancel()
	}
	retireCtx, retireCancel := context.WithCancel(context.Background())
	m.lastRetirementCancel = retireCancel
	m.lastRetirementMu.Unlock()

	if log != nil {
		log.Warnln("[Reload] Retiring old control plane")
	}
	retirementDone := make(chan struct{})
	// lastRetirementMu only serializes cancellation/replacement of the previous
	// retirement goroutine. The timing metadata below belongs to the reload
	// manager state itself, so it is read under m.mu instead. This split is safe
	// because reload requests are handled by a single worker goroutine.
	m.mu.Lock()
	m.pendingRetirementDone = retirementDone
	drainBudget := remainingReloadRetirementBudget(m.pendingReloadRequestedAt, reloadTotalSwitchBudget)
	staleBeforeNs := m.pendingReloadRequestedAtMono
	m.mu.Unlock()

	go func(done chan struct{}) {
		defer close(done)

		oldControlPlane.MarkRetired()
		retireControlPlaneConnections(log, retireCtx, oldControlPlane, abortConnections, hasOverlap, drainBudget)

		if oldCancel != nil {
			oldCancel()
		}
		if closeErr := oldControlPlane.Close(); closeErr != nil && log != nil {
			log.WithError(closeErr).Warnln("[Reload] Old control plane close did not finish cleanly")
		}
		if successor != nil {
			successor.RunReloadRetirementCleanup(staleBeforeNs)
		}
		if log != nil {
			log.Warnln("[Reload] Retired old control plane")
		}
	}(retirementDone)
}

func (m *reloadManager) refreshPprofServer(log *logrus.Logger, server **http.Server, port uint16) {
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

// dnsConfigFingerprint must be kept in sync with config.Dns. The companion
// TestDNSConfigFingerprintCoversAllDnsFields fails when new top-level DNS
// fields are added without updating this fingerprint.
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
		b.WriteString(f.String(true, true, false))
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
	b.WriteString("optimistic_cache=")
	b.WriteString(strconv.FormatBool(dns.OptimisticCache))
	b.WriteByte(';')
	b.WriteString("optimistic_cache_ttl=")
	b.WriteString(strconv.Itoa(dns.OptimisticCacheTtl))
	b.WriteByte(';')
	b.WriteString("max_cache_size=")
	b.WriteString(strconv.Itoa(dns.MaxCacheSize))
	b.WriteByte(';')
	return b.String()
}
