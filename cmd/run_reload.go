/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/control"
	"github.com/sirupsen/logrus"
)

var errTCHookOwnershipRestore = errors.New("TC HookSet ownership restore failed")

func canRecoverReloadReadinessFailure(result reloadReadyWaitResult) bool {
	return result == reloadReadyWaitFailed
}

func tryQueueReloadRequest(
	log *logrus.Logger,
	reloadReqs chan<- reloadRequest,
	reloadActive *atomic.Bool,
	reloadPending *atomic.Bool,
	req reloadRequest,
) bool {
	if reloadPending != nil && !reloadPending.CompareAndSwap(false, true) {
		if log != nil {
			log.Warnln("[Reload] Reload already in progress or handoff pending; ignoring this signal")
		}
		restoreRejectedReloadProgress(reloadActive, false)
		return false
	}
	beginReloadProxyFailureSuppression()
	select {
	case reloadReqs <- req:
		return true
	default:
		if reloadPending != nil {
			reloadPending.Store(false)
		}
		endReloadProxyFailureSuppression()
		if log != nil {
			log.Warnln("[Reload] Last reload request still processing, ignore this one")
		}
		restoreRejectedReloadProgress(reloadActive, true)
		return false
	}
}

func restoreRejectedReloadProgress(reloadActive *atomic.Bool, forceProcessing bool) {
	if forceProcessing || (reloadActive != nil && reloadActive.Load()) {
		_ = setRunSignalProgress(consts.ReloadBusy, reloadBusyActiveMessage)
		return
	}
	_ = setRunSignalProgress(consts.ReloadBusy, reloadBusyRetiringMessage)
}

func clearRejectedReloadProgress() {
	code, _, err := getRunSignalProgress()
	if err != nil {
		return
	}
	if code == consts.ReloadBusy {
		_ = setRunSignalProgress(consts.ReloadDone, "")
	}
}

func clearReloadPending(flag *atomic.Bool) {
	if flag != nil {
		flag.Store(false)
	}
	endReloadProxyFailureSuppression()
	clearRejectedReloadProgress()
}

// shouldUseStagedHotHandoff reports whether a reload may overlap the outgoing
// and incoming datapaths on a shared listener.
//
// Overlapping generations both publish routing state, and what keeps the kernel
// from observing a half-written rule set is the routing epoch's prepared-slot
// indirection. A fresh datapath (port or BPF change) cannot overlap, and
// neither can a cold start without a listener.
func shouldUseStagedHotHandoff(freshDatapathReload, listenerPresent bool) bool {
	return !freshDatapathReload && listenerPresent
}

func shouldStreamStagedDnsCache(
	stagedHotHandoff,
	dnsConfigUnchanged,
	ipVersionPreferenceUnchanged bool,
) bool {
	return stagedHotHandoff && dnsConfigUnchanged && ipVersionPreferenceUnchanged
}

func releaseReloadPendingAfterRetirement(flag *atomic.Bool, retirementDone <-chan struct{}) {
	if flag == nil {
		endReloadProxyFailureSuppression()
		return
	}
	if retirementDone == nil {
		clearReloadPending(flag)
		return
	}
	// The routing epoch bridge has only two reusable slots. Keep reloadPending
	// set until the retiring generation has stopped execution and closed, so a
	// third staged reload cannot overwrite a slot that still belongs to a
	// draining flow.
	go func() {
		<-retirementDone
		clearReloadPending(flag)
	}()
}

func remainingReloadRetirementBudget(startedAt time.Time, budget time.Duration) time.Duration {
	if budget <= 0 {
		return 0
	}
	if startedAt.IsZero() {
		return budget
	}
	remaining := budget - time.Since(startedAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// buildRunShutdownHandoff preserves the historical fast-exit path: process
// termination does not wait for reload transitions or retirement cleanup.
// Graceful shutdown freezes the supervisor first so every generation has one
// clear cleanup owner.
func buildRunShutdownHandoff(manager *reloadManager, supervisor *runtimeSupervisor, current *runtimeGeneration, fastExit bool) *signalShutdownStagedHandoff {
	if fastExit {
		return manager.buildShutdownHandoff()
	}
	shutdownSnapshot := manager.shutdownSupervisor(supervisor)
	handoff := manager.buildShutdownHandoffWithSupervisor(shutdownSnapshot, current)
	if current != nil && current.cancel != nil {
		if handoff == nil {
			handoff = &signalShutdownStagedHandoff{}
		}
		if handoff.newCancel == nil {
			handoff.newCancel = current.cancel
		}
	}
	return handoff
}

func prepareFreshDatapathCutover(log *logrus.Logger, handoff *stagedReloadHandoff) error {
	if handoff == nil || !handoff.freshDatapath {
		return fmt.Errorf("missing fresh datapath handoff")
	}
	if handoff.oldControlPlane == nil || handoff.newControlPlane == nil {
		return fmt.Errorf("missing control plane for fresh datapath cutover")
	}
	if handoff.oldListener == nil {
		return fmt.Errorf("missing previous listener for fresh datapath cutover")
	}
	handoff.freshCutoverStarted = true
	if err := handoff.oldControlPlane.StopDNSListener(); err != nil {
		return fmt.Errorf("stop previous DNS listener: %w", err)
	}
	if log != nil && log.IsLevelEnabled(logrus.DebugLevel) {
		log.Debugln("[Reload] Previous datapath remains active until the fresh candidate is ready")
	}
	return nil
}

func rollbackFreshDatapathReloadHandoff(log *logrus.Logger, handoff *stagedReloadHandoff) (*control.Listener, error) {
	if handoff == nil || handoff.oldControlPlane == nil || handoff.oldConf == nil {
		return nil, fmt.Errorf("missing previous generation for fresh datapath rollback")
	}
	var rollbackCleanupErrs []error
	defer func() {
		// The candidate generation applied its disable_thp policy process-wide
		// during preparation; a rollback must restore the previous generation's
		// policy (prctl(PR_SET_THP_DISABLE) is per-mm and idempotent).
		configureTransparentHugePages(log, handoff.oldConf.Global.DisableTHP)
	}()
	if handoff.provisionalOwner && handoff.newControlPlane != nil {
		handoff.newControlPlane.UnregisterProvisionalRoutingEpochExecutionOwner()
		handoff.provisionalOwner = false
	}
	if handoff.flowDatapathAdopted && handoff.newControlPlane != nil {
		if err := handoff.oldControlPlane.AdoptProcessFlowDatapath(handoff.newControlPlane); err != nil {
			rollbackCleanupErrs = append(rollbackCleanupErrs, fmt.Errorf("restore process flow datapath: %w", err))
		} else {
			handoff.flowDatapathAdopted = false
		}
	}
	if handoff.tcHookSetAdopted && handoff.newControlPlane != nil {
		if err := restoreTCHookSetOwnershipFunc(handoff.newControlPlane, handoff.oldControlPlane); err != nil {
			rollbackCleanupErrs = append(rollbackCleanupErrs,
				errTCHookOwnershipRestore,
				fmt.Errorf("restore previous TC HookSet owner: %w", err),
			)
			return nil, errors.Join(rollbackCleanupErrs...)
		}
		handoff.tcHookSetAdopted = false
	}
	if handoff.hookFlipCommitted && handoff.newControlPlane != nil {
		if err := handoff.newControlPlane.RollbackPreparedBpfHookFlip(); err != nil {
			rollbackCleanupErrs = append(rollbackCleanupErrs, fmt.Errorf("restore previous BPF hook flip: %w", err))
		} else {
			handoff.hookFlipCommitted = false
		}
	}
	if handoff.tcHookHandoffPrepared && !handoff.tcHookSetAdopted && !handoff.hookFlipCommitted && handoff.newControlPlane != nil {
		if err := handoff.newControlPlane.ClearPreparedTCHookHandoff(); err != nil {
			rollbackCleanupErrs = append(rollbackCleanupErrs, fmt.Errorf("clear prepared TC HookSet handoff: %w", err))
		} else {
			handoff.tcHookHandoffPrepared = false
		}
	}
	if handoff.newControlPlane != nil {
		if err := handoff.newControlPlane.DetachBpfHooks(); err != nil {
			rollbackCleanupErrs = append(rollbackCleanupErrs, fmt.Errorf("detach fresh datapath hooks: %w", err))
		}
	}
	if handoff.preparedGeneration != nil {
		if err := handoff.preparedGeneration.cleanup(); err != nil {
			rollbackCleanupErrs = append(rollbackCleanupErrs, fmt.Errorf("cleanup fresh datapath generation: %w", err))
		}
	} else {
		if handoff.newCancel != nil {
			handoff.newCancel()
		}
		if handoff.newControlPlane != nil {
			if err := handoff.newControlPlane.Close(); err != nil && log != nil {
				log.WithError(err).Warnln("[Reload] Failed to close fresh datapath control plane during rollback")
			}
		}
	}
	if len(rollbackCleanupErrs) > 0 {
		return nil, errors.Join(rollbackCleanupErrs...)
	}
	if !handoff.oldRuntimeStopped {
		if err := handoff.oldControlPlane.RestartDNSListener(); err != nil {
			return nil, fmt.Errorf("restart previous DNS listener: %w", err)
		}
		if log != nil {
			log.Warnln("[Reload] Discarded fresh datapath candidate; previous generation remained active")
		}
		return handoff.oldListener, nil
	}

	recoveredListener, err := listenControlPlaneInDaeNetns(handoff.oldControlPlane, handoff.oldConf.Global.TproxyPort)
	if err != nil {
		return nil, fmt.Errorf("restore previous listener: %w", err)
	}
	if err := handoff.oldControlPlane.RestoreDatapathForReloadRollback(); err != nil {
		_ = recoveredListener.Close()
		return nil, err
	}
	if err := handoff.oldControlPlane.RestartDNSListener(); err != nil {
		_ = recoveredListener.Close()
		return nil, fmt.Errorf("restart previous DNS listener: %w", err)
	}
	if log != nil {
		log.Warnln("[Reload] Restored previous generation after fresh datapath handoff failure")
	}
	return recoveredListener, nil
}

func restartRecoveredControlPlane(
	log *logrus.Logger,
	sigs <-chan os.Signal,
	runStateChanges chan<- struct{},
	c *control.ControlPlane,
	listener *control.Listener,
) error {
	if c == nil || listener == nil {
		return fmt.Errorf("missing recovered control plane or listener")
	}
	readyChan := make(chan bool, 1)
	go func() {
		defer func() {
			select {
			case readyChan <- false:
			default:
			}
		}()
		if err := serveControlPlaneFunc(c, readyChan, listener); err != nil && log != nil {
			log.Errorln("ListenAndServe:", err)
		}
		notifyRunStateChange(runStateChanges)
	}()
	waitResult, termSig := waitReloadReadyOrSignal(log, sigs, readyChan, reloadReadyTimeout)
	if waitResult == reloadReadyWaitSignal && termSig != nil {
		return fmt.Errorf("received termination signal while restoring previous generation: %v", termSig.String())
	}
	if waitResult == reloadReadyWaitTimeout {
		return fmt.Errorf("restored listener timed out after %v", reloadReadyTimeout)
	}
	if waitResult != reloadReadyWaitReady {
		return fmt.Errorf("restored listener failed before becoming ready")
	}
	return nil
}

func restoreStagedReloadHandoff(log *logrus.Logger, handoff *stagedReloadHandoff) error {
	if handoff == nil {
		return fmt.Errorf("staged reload handoff is nil")
	}

	var errs []error
	if err := rollbackStagedReloadHandoff(log, handoff); err != nil {
		if errors.Is(err, errTCHookOwnershipRestore) {
			return err
		}
		errs = append(errs, err)
	}
	if handoff.oldControlPlane == nil {
		errs = append(errs, fmt.Errorf("previous control plane is nil"))
		return errors.Join(errs...)
	}
	if handoff.oldListener == nil {
		errs = append(errs, fmt.Errorf("previous listener is nil"))
	} else if err := restoreListenerSocketsFunc(handoff.oldControlPlane, handoff.oldListener); err != nil {
		errs = append(errs, fmt.Errorf("republish previous listeners: %w", err))
	}
	if err := restoreReloadDatapathFunc(handoff.oldControlPlane); err != nil {
		errs = append(errs, fmt.Errorf("rebuild previous datapath: %w", err))
	}
	if !handoff.oldDNSListenerActive {
		if err := restoreDNSListenerFunc(handoff.oldControlPlane); err != nil {
			errs = append(errs, fmt.Errorf("restart previous DNS listener: %w", err))
		}
	}
	return errors.Join(errs...)
}

func rollbackStagedReloadHandoff(log *logrus.Logger, handoff *stagedReloadHandoff) error {
	if handoff == nil {
		return nil
	}
	var errs []error
	defer func() {
		// The candidate generation applied its disable_thp policy process-wide
		// during preparation; a rollback must restore the previous generation's
		// policy (prctl(PR_SET_THP_DISABLE) is per-mm and idempotent).
		if handoff.oldConf != nil {
			configureTransparentHugePages(log, handoff.oldConf.Global.DisableTHP)
		}
		if handoff.oldConnectivityPaused && handoff.oldControlPlane != nil {
			handoff.oldControlPlane.ResumeOutboundConnectivityUpdates()
			handoff.oldConnectivityPaused = false
		}
	}()

	if handoff.newControlPlane != nil && (handoff.dnsControllerMoved || handoff.dnsListenerMoved) {
		listenerActive, err := handoff.newControlPlane.RestorePreparedDNSRuntimeForRollback(
			handoff.oldControlPlane,
			handoff.dnsControllerMoved,
			handoff.dnsListenerMoved,
		)
		if err != nil {
			errs = append(errs, err)
		} else {
			handoff.dnsControllerMoved = false
			handoff.dnsListenerMoved = false
			handoff.oldDNSListenerActive = listenerActive
		}
	}

	if handoff.tcHookSetAdopted && handoff.newControlPlane != nil {
		if err := restoreTCHookSetOwnershipFunc(handoff.newControlPlane, handoff.oldControlPlane); err != nil {
			errs = append(errs,
				errTCHookOwnershipRestore,
				fmt.Errorf("restore previous TC HookSet owner: %w", err),
			)
			return errors.Join(errs...)
		}
		handoff.tcHookSetAdopted = false
	}
	if handoff.hookFlipCommitted && handoff.newControlPlane != nil {
		if err := handoff.newControlPlane.RollbackPreparedBpfHookFlip(); err != nil {
			errs = append(errs, fmt.Errorf("restore previous BPF hooks: %w", err))
		} else {
			handoff.hookFlipCommitted = false
		}
	}
	if handoff.tcHookHandoffPrepared && !handoff.tcHookSetAdopted && !handoff.hookFlipCommitted && handoff.newControlPlane != nil {
		if err := handoff.newControlPlane.ClearPreparedTCHookHandoff(); err != nil {
			errs = append(errs, fmt.Errorf("clear prepared TC HookSet handoff: %w", err))
		} else {
			handoff.tcHookHandoffPrepared = false
		}
	}

	if handoff.bpfTransferred && handoff.oldControlPlane != nil && handoff.newControlPlane != nil {
		handoff.oldControlPlane.InjectBpf(handoff.newControlPlane.EjectBpf())
		handoff.bpfTransferred = false
	}

	if handoff.newControlPlane != nil {
		handoff.newControlPlane.ClearReloadDnsCacheSource()
		// Self-noops when this handoff never reserved a peer slot, so it does
		// not need a flag mirroring which reload shape got here.
		if err := handoff.newControlPlane.RollbackPreparedRoutingEpoch(); err != nil {
			errs = append(errs, fmt.Errorf("restore previous routing epoch: %w", err))
			if log != nil {
				log.WithError(err).Errorln("[Reload] Failed to restore previous routing epoch before closing staged control plane")
			}
		}
	}

	if handoff.preparedGeneration != nil {
		if err := handoff.preparedGeneration.cleanup(); err != nil {
			errs = append(errs, fmt.Errorf("clean up staged generation: %w", err))
			if log != nil {
				log.WithError(err).Warnln("[Reload] Failed to clean up staged generation during rollback")
			}
		}
	} else {
		if handoff.newListener != nil {
			if err := handoff.newListener.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close prepared listener: %w", err))
				if log != nil {
					log.WithError(err).Warnln("[Reload] Failed to close prepared listener during rollback")
				}
			}
		}
		if handoff.newCancel != nil {
			handoff.newCancel()
		}
		if handoff.newControlPlane != nil {
			if err := handoff.newControlPlane.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close staged control plane: %w", err))
				if log != nil {
					log.WithError(err).Warnln("[Reload] Failed to close staged control plane during rollback")
				}
			}
		}
	}
	return errors.Join(errs...)
}

func wrapReloadTimeoutError(stage string, err error, timeout time.Duration) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s timed out after %v: %w", stage, timeout, err)
	}
	return err
}

func waitReloadReadyOrSignal(
	log *logrus.Logger,
	sigs <-chan os.Signal,
	readyChan <-chan bool,
	timeout time.Duration,
) (result reloadReadyWaitResult, termSig os.Signal) {
	var timer *time.Timer
	var timeoutCh <-chan time.Time
	if timeout > 0 {
		timer = time.NewTimer(timeout)
		defer timer.Stop()
		timeoutCh = timer.C
	}

	for {
		select {
		case ready := <-readyChan:
			if ready {
				return reloadReadyWaitReady, nil
			}
			return reloadReadyWaitFailed, nil
		case sig := <-sigs:
			switch sig {
			case nil, syscall.SIGHUP:
				continue
			case syscall.SIGUSR1, syscall.SIGUSR2:
				if log != nil {
					log.Warnln("[Reload] Signal received while current reload is still becoming ready; ignoring it")
				}
				continue
			case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
				return reloadReadyWaitSignal, sig
			default:
				if sig != nil && log != nil {
					log.Infof("Received signal while waiting for reload readiness: %v", sig.String())
				}
			}
		case <-timeoutCh:
			return reloadReadyWaitTimeout, nil
		}
	}
}
