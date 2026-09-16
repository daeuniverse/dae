/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/logger"
	"github.com/mohae/deepcopy"
	"github.com/okzk/sdnotify"
	"github.com/sirupsen/logrus"
)

// reloadWorker drives the reload state machine for one Run invocation: it
// consumes reload requests, loads the new config, prepares a candidate
// generation (staged-hot handoff, fresh datapath handoff, or the legacy
// shared-BPF path), and hands the candidate to Run's signal loop for
// readiness-wait, publish, and retirement of the old generation.
type reloadWorker struct {
	// Immutable run context.
	externGeoDataDirs []string
	processSessions   *control.SessionManager
	runtimeSupervisor *runtimeSupervisor
	reloadManager     *reloadManager
	runStateChanges   chan<- struct{}

	// Mutable run state shared with Run's signal loop. Field names mirror
	// Run's original local variables; the signal loop advances c, conf,
	// currCancel, and listener after publishing a candidate generation, and
	// this worker swaps log when a reload changes the log level.
	log         *logrus.Logger
	conf        *config.Config
	c           *control.ControlPlane
	currCancel  context.CancelFunc
	listener    *control.Listener
	pprofServer *http.Server
}

// attachPreparedSessionManager attaches the process-owned session manager to a
// newly built control plane. A prior construction error is returned unchanged
// so callers can keep their existing failure tails. An attach failure closes
// the candidate before it is returned, matching the previous inline copies.
func attachPreparedSessionManager(c *control.ControlPlane, manager *control.SessionManager, err error) error {
	if err != nil || c == nil {
		return err
	}
	if attachErr := c.AttachSessionManager(manager); attachErr != nil {
		_ = c.Close()
		return attachErr
	}
	return nil
}

// run consumes reload requests until the process exits. It is started once by
// Run and performs no generation publication itself; every prepared candidate
// is published from Run's signal loop after it reports readiness.
func (w *reloadWorker) run() {
	var err error
	for req := range w.reloadManager.reloadReqs {
		w.reloadManager.reloadActive.Store(true)
		req = w.reloadManager.coalesceReloadRequest(req)
		reloadStartedAt := req.requestedAt
		reloadStartedAtMono := req.requestedAtMono

		if req.isSuspend {
			w.log.Infoln("[Reload] Received suspend signal; prepare to suspend")
		} else {
			w.log.Infoln("[Reload] Received reload signal; prepare to reload")
		}
		_ = sdnotify.Reloading()
		_ = setRunSignalProgress(consts.ReloadProcessing, "")
		w.reloadManager.setReloadError(nil)
		resetReloadProxyRuntimeState()
		resetReloadFilterRegexpCache()

		// Load new config.
		abortConnections := os.Remove(AbortFile) == nil
		w.log.Infoln("[Reload] Load new config")
		var newConf *config.Config
		if req.isSuspend {
			newConf, err = emptyConfig()
			if err != nil {
				w.log.WithFields(logrus.Fields{
					"err": err,
				}).Errorln("[Reload] Failed to reload")
				w.reloadManager.failReloadAttempt(err)
				continue
			}
			newConf.Global = deepcopy.Copy(w.conf.Global).(config.Global)
			newConf.Global.WanInterface = nil
			newConf.Global.LanInterface = nil
			newConf.Global.LogLevel = "warning"
		} else {
			var includes []string
			newConf, includes, err = readConfig(cfgFile)
			if err != nil {
				w.log.WithFields(logrus.Fields{
					"err": err,
				}).Errorln("[Reload] Failed to reload")
				w.reloadManager.failReloadAttempt(err)
				continue
			}
			w.log.Infof("Include config files: [%v]", strings.Join(includes, ", "))
		}
		// Re-apply the new log level/formatter in place instead of swapping the
		// w.log pointer: the signal loop and the fast-exit path read w.log
		// concurrently with this worker, while the logrus mutators used by
		// SetLogger (SetLevel/SetFormatter) are mutex-safe on a shared
		// *logrus.Logger. Keeping one logger instance also propagates the new
		// level to every component that already captured the pointer, which a
		// fresh logger silently left on the old one.
		oldLogOutput := w.log.Out
		logger.SetLogger(w.log, newConf.Global.LogLevel, disableTimestamp, nil)
		logger.SetLogger(logrus.StandardLogger(), newConf.Global.LogLevel, disableTimestamp, nil)
		logrus.SetOutput(oldLogOutput)
		if !req.isSuspend {
			if deferred := preserveReloadInterfaceBindings(w.conf, newConf); len(deferred) > 0 {
				w.log.WithField("bindings", strings.Join(deferred, ",")).Warnln("[Reload] Deferring interface removal or role change until cold start to preserve established flows")
			}
		}

		portChanged := w.conf.Global.TproxyPort != newConf.Global.TproxyPort
		datapathChanged := bpfDatapathChanged(w.conf, newConf)
		freshDatapathReload := portChanged || datapathChanged
		stagedHotHandoff := shouldUseStagedHotHandoff(freshDatapathReload, w.listener != nil)
		freshDatapathHandoff := freshDatapathReload && w.listener != nil
		if !w.reloadManager.beginReloadTransition() {
			reloadErr := errRuntimeSupervisorClosed
			w.reloadManager.setReloadError(reloadErr)
			w.log.WithError(reloadErr).Warnln("[Reload] Ignoring reload while shutdown is in progress")
			w.reloadManager.reloadActive.Store(false)
			clearReloadPending(&w.reloadManager.reloadPending)
			continue
		}
		transitionHeld := true
		releaseReloadTransition := func() {
			if transitionHeld {
				w.reloadManager.endReloadTransition()
				transitionHeld = false
			}
		}
		// failSupervisorStep aborts a prepared candidate whose supervisor
		// registration failed and keeps the current generation active. step
		// labels the failure context; preCleanup runs before and postCleanup
		// after the candidate teardown (the legacy path returns shared BPF
		// ownership before teardown and restarts the old DNS listener after).
		failSupervisorStep := func(err error, step string, candidate *runtimeGeneration, preCleanup, postCleanup func()) {
			reloadErr := fmt.Errorf("%s: %w", step, err)
			w.reloadManager.setReloadError(reloadErr)
			// The candidate already applied its disable_thp policy process-wide
			// before the supervisor steps; restore the still-active generation's
			// policy so a failed reload cannot leak the rejected memory policy
			// (prctl(PR_SET_THP_DISABLE) is per-mm and idempotent).
			configureTransparentHugePages(w.log, w.conf.Global.DisableTHP)
			if preCleanup != nil {
				preCleanup()
			}
			if closeErr := candidate.cleanup(); closeErr != nil {
				w.log.WithError(closeErr).Warnf("[Reload] Failed to close candidate generation after %s failure", step)
			}
			if postCleanup != nil {
				postCleanup()
			}
			w.log.WithError(reloadErr).Errorln("[Reload] Failed to prepare reload candidate; keeping current generation active")
			w.reloadManager.failReloadAttempt(reloadErr)
			releaseReloadTransition()
		}

		// New control plane.
		obj := w.c.PeekBpf()
		if freshDatapathReload {
			obj = nil
		} else if !stagedHotHandoff {
			obj = w.c.EjectBpf()
		}
		var reloadBpf any
		if obj != nil {
			reloadBpf = obj
		}
		if portChanged {
			w.log.Warnf("[Reload] Tproxy port changed from %d to %d; will perform a full reload of eBPF programs", w.conf.Global.TproxyPort, newConf.Global.TproxyPort)
		} else if datapathChanged {
			w.log.Warnln("[Reload] Kernel datapath input changed (interface/somark/map-size); will perform a fresh datapath handoff")
		}

		dnsConfigUnchanged := dnsConfigEqual(w.conf, newConf)
		ipVersionPreferenceUnchanged := w.conf.Dns.IpVersionPrefer == newConf.Dns.IpVersionPrefer
		streamStagedDnsCache := shouldStreamStagedDnsCache(
			stagedHotHandoff,
			dnsConfigUnchanged,
			ipVersionPreferenceUnchanged,
		)
		dnsCache, rollbackDNSCache := cloneReloadDNSCaches(w.conf, newConf, stagedHotHandoff, w.c.CloneDnsCache)
		var stagedListener *control.Listener

		if stagedHotHandoff {
			w.log.Infoln("[Reload] Prepare staged same-port handoff")
			ctx, cancel := context.WithTimeout(context.Background(), reloadPrepareTimeout)
			newC, prepareErr := newPreparedControlPlane(ctx, w.log, reloadBpf, dnsCache, newConf, w.externGeoDataDirs, dnsConfigUnchanged, true)
			prepareErr = attachPreparedSessionManager(newC, w.processSessions, prepareErr)
			if prepareErr != nil {
				reloadErr := wrapReloadTimeoutError("prepare staged reload", prepareErr, reloadPrepareTimeout)
				w.reloadManager.setReloadError(reloadErr)
				cancel()
				w.log.WithError(reloadErr).Errorln("[Reload] Failed to prepare staged reload; keeping current generation active")
				w.reloadManager.failReloadAttempt(reloadErr)
				releaseReloadTransition()
				continue
			}

			stagedListener, listenErr := cloneControlListenerFunc(w.listener)
			if listenErr != nil {
				reloadErr := fmt.Errorf("clone listener: %w", listenErr)
				w.reloadManager.setReloadError(reloadErr)
				if closeErr := (&runtimeGeneration{controlPlane: newC, cancel: cancel}).cleanup(); closeErr != nil {
					w.log.WithError(closeErr).Warnln("[Reload] Failed to close prepared staged generation")
				}
				w.log.WithError(reloadErr).Errorln("[Reload] Failed to stage listener; keeping current generation active")
				w.reloadManager.failReloadAttempt(reloadErr)
				releaseReloadTransition()
				continue
			}

			oldC := w.c
			oldCancel := w.currCancel
			oldConf := w.conf
			oldListener := w.listener
			if err := linkRoutingEpochPeerFunc(oldC, newC); err != nil {
				reloadErr := fmt.Errorf("link staged routing epochs: %w", err)
				w.reloadManager.setReloadError(reloadErr)
				if closeErr := stagedListener.Close(); closeErr != nil {
					w.log.WithError(closeErr).Warnln("[Reload] Failed to close staged listener after epoch link failure")
				}
				if closeErr := (&runtimeGeneration{controlPlane: newC, cancel: cancel}).cleanup(); closeErr != nil {
					w.log.WithError(closeErr).Warnln("[Reload] Failed to close staged generation after epoch link failure")
				}
				w.log.WithError(reloadErr).Errorln("[Reload] Failed to prepare staged reload; keeping current generation active")
				w.reloadManager.failReloadAttempt(reloadErr)
				releaseReloadTransition()
				continue
			}

			if dnsCachePolicyEqual(oldConf, newConf) {
				if streamStagedDnsCache {
					newC.SetReloadDnsCacheStreamSource(oldC.StreamDnsCacheForReload, oldC.PolicyIdentity().Hash())
				} else {
					newC.SetReloadDnsCacheSource(oldC.CloneDnsCache)
				}
			}
			newC.InheritDialerHealthFrom(oldC)
			configureTransparentHugePages(w.log, newConf.Global.DisableTHP)
			activeGeneration := &runtimeGeneration{
				controlPlane: oldC,
				listener:     oldListener,
				cancel:       oldCancel,
				conf:         oldConf,
			}
			candidateGeneration := &runtimeGeneration{
				controlPlane: newC,
				listener:     stagedListener,
				cancel:       cancel,
				conf:         newConf,
			}
			if err := w.runtimeSupervisor.replaceActive(activeGeneration); err != nil {
				failSupervisorStep(err, "record active generation for staged reload", candidateGeneration, nil, nil)
				continue
			}
			if err := w.runtimeSupervisor.installPrepared(candidateGeneration); err != nil {
				failSupervisorStep(err, "install staged reload candidate", candidateGeneration, nil, nil)
				continue
			}
			handoff := newStagedReloadHandoff(activeGeneration, candidateGeneration, abortConnections)
			handoff.preparedDNSHandoff = true
			handoff.sharedBpfHandoff = true
			w.reloadManager.setPendingStagedHandoff(handoff, reloadStartedAt, reloadStartedAtMono)
			w.reloadManager.beginHandoff()
			releaseReloadTransition()
			notifyRunStateChange(w.runStateChanges)
			continue
		}

		if freshDatapathHandoff {
			w.log.Infoln("[Reload] Prepare fresh datapath handoff")
			ctx, cancel := context.WithTimeout(context.Background(), reloadPrepareTimeout)
			freshState, prepareErr := w.c.SnapshotFreshDatapathState()
			var newC *control.ControlPlane
			if prepareErr == nil {
				newC, prepareErr = newPreparedControlPlane(ctx, w.log, freshState, dnsCache, newConf, w.externGeoDataDirs, false, true)
			}
			prepareErr = attachPreparedSessionManager(newC, w.processSessions, prepareErr)
			if prepareErr != nil {
				reloadErr := wrapReloadTimeoutError("prepare fresh datapath reload", prepareErr, reloadPrepareTimeout)
				w.reloadManager.setReloadError(reloadErr)
				cancel()
				w.log.WithError(reloadErr).Errorln("[Reload] Failed to prepare fresh datapath reload; keeping current generation active")
				w.reloadManager.failReloadAttempt(reloadErr)
				releaseReloadTransition()
				continue
			}

			stagedListener, err = listenControlPlaneInDaeNetns(newC, newConf.Global.TproxyPort)
			if err != nil {
				reloadErr := fmt.Errorf("prepare fresh datapath listener: %w", err)
				w.reloadManager.setReloadError(reloadErr)
				if closeErr := (&runtimeGeneration{controlPlane: newC, listener: stagedListener, cancel: cancel}).cleanup(); closeErr != nil {
					w.log.WithError(closeErr).Warnln("[Reload] Failed to close prepared fresh datapath generation")
				}
				w.log.WithError(reloadErr).Errorln("[Reload] Failed to prepare fresh datapath listener; keeping current generation active")
				w.reloadManager.failReloadAttempt(reloadErr)
				releaseReloadTransition()
				continue
			}

			oldC := w.c
			oldCancel := w.currCancel
			oldConf := w.conf
			oldListener := w.listener

			newC.InheritDialerHealthFrom(oldC)
			configureTransparentHugePages(w.log, newConf.Global.DisableTHP)
			activeGeneration := &runtimeGeneration{
				controlPlane: oldC,
				listener:     oldListener,
				cancel:       oldCancel,
				conf:         oldConf,
			}
			candidateGeneration := &runtimeGeneration{
				controlPlane: newC,
				listener:     stagedListener,
				cancel:       cancel,
				conf:         newConf,
			}
			if err := w.runtimeSupervisor.replaceActive(activeGeneration); err != nil {
				failSupervisorStep(err, "record active generation for fresh datapath reload", candidateGeneration, nil, nil)
				continue
			}
			if err := w.runtimeSupervisor.installPrepared(candidateGeneration); err != nil {
				failSupervisorStep(err, "install fresh datapath reload candidate", candidateGeneration, nil, nil)
				continue
			}
			handoff := newStagedReloadHandoff(activeGeneration, candidateGeneration, abortConnections)
			handoff.freshDatapath = true
			w.reloadManager.setPendingStagedHandoff(handoff, reloadStartedAt, reloadStartedAtMono)
			w.reloadManager.beginHandoff()
			releaseReloadTransition()
			notifyRunStateChange(w.runStateChanges)
			continue
		}

		// Stop old DNS listener before creating new one to avoid port conflicts
		if err := w.c.StopDNSListener(); err != nil {
			w.log.Warnf("[Reload] Failed to stop old DNS listener: %v", err)
		}

		w.log.Infoln("[Reload] Load new control plane")
		ctx, cancel := context.WithTimeout(context.Background(), reloadPrepareTimeout)
		newC, err := newControlPlane(ctx, w.log, reloadBpf, dnsCache, newConf, w.externGeoDataDirs, dnsConfigUnchanged, true)
		err = attachPreparedSessionManager(newC, w.processSessions, err)

		var newCancel context.CancelFunc
		if err != nil {
			w.reloadManager.setReloadError(wrapReloadTimeoutError("build new control plane", err, reloadPrepareTimeout))
			w.log.WithFields(logrus.Fields{
				"err": err,
			}).Errorln("[Reload] Failed to reload; try to roll back configuration")
			cancel()

			// Load last config back.
			if freshDatapathReload {
				w.log.Warnln("[Reload] BPF objects already replaced; attempting rollback with fresh eBPF objects")
				obj = nil
				reloadBpf = nil
			}
			ctx, cancel = context.WithTimeout(context.Background(), reloadPrepareTimeout)
			newC, err = newControlPlane(ctx, w.log, reloadBpf, rollbackDNSCache, w.conf, w.externGeoDataDirs, false, true)
			err = attachPreparedSessionManager(newC, w.processSessions, err)
			err = wrapReloadTimeoutError("rollback control plane", err, reloadPrepareTimeout)
			if err != nil {
				_ = sdnotify.Stopping()
				if obj != nil && !stagedHotHandoff {
					_ = obj.Close()
				}
				_ = w.c.Close()
				cancel()
				w.log.WithFields(logrus.Fields{
					"err": err,
				}).Fatalln("[Reload] Failed to roll back configuration")
			}
			newConf = w.conf
			newCancel = cancel
			w.log.Errorln("[Reload] Last reload failed; rolled back configuration")
		} else {
			newCancel = cancel
			w.log.Infoln("[Reload] Prepared new control plane")
		}

		if stagedListener == nil {
			stagedListener, err = listenControlPlaneInDaeNetns(newC, newConf.Global.TproxyPort)
			if err != nil {
				reloadErr := fmt.Errorf("prepare new listener: %w", err)
				w.reloadManager.setReloadError(reloadErr)
				if closeErr := (&runtimeGeneration{controlPlane: newC, listener: stagedListener, cancel: newCancel}).cleanup(); closeErr != nil {
					w.log.WithError(closeErr).Warnln("[Reload] Failed to clean up after listener preparation error")
				}
				if obj != nil && !stagedHotHandoff {
					w.c.InjectBpf(obj)
				}
				if restartErr := w.c.RestartDNSListener(); restartErr != nil {
					w.log.WithError(restartErr).Warnln("[Reload] Failed to restart previous DNS listener after reload preparation error")
				}
				w.log.WithError(reloadErr).Errorln("[Reload] Failed to prepare listener; keeping current generation active")
				w.reloadManager.failReloadAttempt(reloadErr)
				releaseReloadTransition()
				continue
			}
		}

		// Non-staged shared-BPF paths transfer ownership before the candidate
		// can serve. The supervisor still keeps the old runtime tuple active
		// until the candidate reports ready.
		if !stagedHotHandoff && !freshDatapathReload {
			newC.InjectBpf(obj)
		}

		var oldListener *control.Listener
		if w.listener != nil {
			oldListener = w.listener
		}

		// Prepare a candidate without replacing the live runtime tuple. The
		// legacy path has already moved its shared BPF object above, so record
		// that ownership transfer to avoid repeating it after readiness.
		oldC := w.c
		oldCancel := w.currCancel
		oldConf := w.conf

		newC.InheritDialerHealthFrom(oldC)
		configureTransparentHugePages(w.log, newConf.Global.DisableTHP)
		activeGeneration := &runtimeGeneration{
			controlPlane: oldC,
			listener:     oldListener,
			cancel:       oldCancel,
			conf:         oldConf,
		}
		candidateGeneration := &runtimeGeneration{
			controlPlane: newC,
			listener:     stagedListener,
			cancel:       newCancel,
			conf:         newConf,
		}
		// The legacy path moved its shared BPF object above; on supervisor
		// failure the ownership must return before candidate teardown, and the
		// old DNS listener restarts after it.
		restoreBpfOwnership := func() {
			if !freshDatapathReload && oldC != nil {
				oldC.InjectBpf(newC.EjectBpf())
			}
		}
		restartOldDNSListener := func() {
			if oldC != nil {
				if restartErr := oldC.RestartDNSListener(); restartErr != nil {
					w.log.WithError(restartErr).Warnln("[Reload] Failed to restart previous DNS listener after supervisor failure")
				}
			}
		}
		if err := w.runtimeSupervisor.replaceActive(activeGeneration); err != nil {
			failSupervisorStep(err, "record active generation for reload", candidateGeneration, restoreBpfOwnership, restartOldDNSListener)
			continue
		}
		if err := w.runtimeSupervisor.installPrepared(candidateGeneration); err != nil {
			failSupervisorStep(err, "install reload candidate", candidateGeneration, restoreBpfOwnership, restartOldDNSListener)
			continue
		}
		handoff := newStagedReloadHandoff(activeGeneration, candidateGeneration, abortConnections)
		handoff.bpfTransferred = !freshDatapathReload
		w.reloadManager.setPendingStagedHandoff(handoff, reloadStartedAt, reloadStartedAtMono)
		w.reloadManager.clearPendingRetirement()
		w.reloadManager.setPendingReloadMetadata(reloadStartedAt, reloadStartedAtMono)
		w.reloadManager.beginHandoff()
		releaseReloadTransition()

		w.reloadManager.refreshPprofServer(&w.pprofServer, newConf.Global.PprofPort)

		notifyRunStateChange(w.runStateChanges)

	}
}
