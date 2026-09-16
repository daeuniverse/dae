/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"

	_ "net/http/pprof"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	outbounddialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/logger"
	"github.com/okzk/sdnotify"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	PidFilePath                    = "/var/run/dae.pid"
	SignalProgressFilePath         = "/var/run/dae.progress"
	reloadTotalSwitchBudget        = 10 * time.Second
	controlPlaneRetirementLogEvery = 5 * time.Second
	reloadPrepareTimeout           = 45 * time.Second
	reloadReadyTimeout             = 45 * time.Second
)

const (
	reloadBusyActiveMessage   = "reload already in progress"
	reloadBusyRetiringMessage = "reload request ignored: previous reload is still retiring old generation"
)

var (
	CheckNetworkLinks = []string{
		"http://edge.microsoft.com/captiveportal/generate_204",
		"http://www.gstatic.com/generate_204",
		"http://www.qualcomm.cn/generate_204",
	}
	beginReloadProxyFailureSuppression = outbounddialer.BeginReloadProxyFailureSuppression
	endReloadProxyFailureSuppression   = outbounddialer.EndReloadProxyFailureSuppression
	resetReloadProxyRuntimeState       = outbounddialer.ResetGlobalProxyStateForReload
	resetReloadFilterRegexpCache       = outbound.ResetRegexpCacheForReload
	listenControlPlaneFunc             = func(c *control.ControlPlane, port uint16) (*control.Listener, error) {
		listener, err := c.Listen(port)
		if err != nil {
			return nil, err
		}
		if err := listener.ValidateCurrentNetns(); err != nil {
			_ = listener.Close()
			return nil, err
		}
		return listener, nil
	}
	cloneControlListenerFunc = func(listener *control.Listener) (*control.Listener, error) { return listener.Clone() }
	linkRoutingEpochPeerFunc = func(oldPlane, newPlane *control.ControlPlane) error { return oldPlane.LinkRoutingEpochPeer(newPlane) }
	serveControlPlaneFunc    = func(c *control.ControlPlane, readyChan chan<- bool, listener *control.Listener) error {
		return c.Serve(readyChan, listener)
	}
	restoreListenerSocketsFunc = func(c *control.ControlPlane, listener *control.Listener) error {
		return c.PublishListenerSockets(listener)
	}
	restoreReloadDatapathFunc = func(c *control.ControlPlane) error {
		return c.RebuildReloadDatapath()
	}
	restoreDNSListenerFunc = func(c *control.ControlPlane) error {
		return c.RestartDNSListener()
	}
	restoreTCHookSetOwnershipFunc = func(candidate, previous *control.ControlPlane) error {
		return candidate.RestorePreparedTCHookSet(previous)
	}
	withDaeNetnsRequiredFunc = func(op string, f func() error) error {
		return control.GetDaeNetns().WithRequired(op, f)
	}
)

type signalShutdownListener interface {
	Close() error
}

type signalShutdownControlPlane interface {
	DetachBpfHooks() error
	AbortConnections() error
	Close() error
}

type signalShutdownNetns interface {
	Close() error
}

type signalShutdownStagedHandoff struct {
	oldListener     signalShutdownListener
	oldControlPlane signalShutdownControlPlane
	oldCancel       context.CancelFunc
	newListener     signalShutdownListener
	newControlPlane signalShutdownControlPlane
	newCancel       context.CancelFunc
}

type reloadRequest struct {
	isSuspend       bool
	requestedAt     time.Time
	requestedAtMono uint64
}

type reloadRetirementControlPlane interface {
	ActiveSessionCount() int
	DrainIdleCh() <-chan struct{}
}

type retirementDrainPlane interface {
	reloadRetirementControlPlane
	AbortConnections() error
	AbortPendingConnections() error
	StopRoutingEpochExecution()
	StopRoutingEpochExecutionWithTimeout(time.Duration)
}

type controlPlaneDrainWaitResult uint8

const (
	controlPlaneDrainIdle controlPlaneDrainWaitResult = iota
	controlPlaneDrainCanceled
	controlPlaneDrainTimeout
)

type reloadReadyWaitResult uint8

const (
	reloadReadyWaitReady reloadReadyWaitResult = iota
	reloadReadyWaitFailed
	reloadReadyWaitSignal
	reloadReadyWaitTimeout
)

type stagedReloadHandoff struct {
	preparedGeneration    *runtimeGeneration
	oldControlPlane       *control.ControlPlane
	oldCancel             context.CancelFunc
	oldConf               *config.Config
	oldListener           *control.Listener
	newControlPlane       *control.ControlPlane
	newCancel             context.CancelFunc
	newListener           *control.Listener
	abortConnections      bool
	freshDatapath         bool
	preparedDNSHandoff    bool
	bpfTransferred        bool
	sharedBpfHandoff      bool
	oldConnectivityPaused bool
	freshCutoverStarted   bool
	flowDatapathAdopted   bool
	oldRuntimeStopped     bool
	dnsControllerMoved    bool
	dnsListenerMoved      bool
	oldDNSListenerActive  bool
	tcHookHandoffPrepared bool
	tcHookSetAdopted      bool
	hookFlipCommitted     bool
	provisionalOwner      bool
}

// newStagedReloadHandoff builds the base handoff from the two supervisor
// generations; path-specific flags (freshDatapath, preparedDNSHandoff,
// bpfTransferred, ...) are set by the caller.
func newStagedReloadHandoff(active, candidate *runtimeGeneration, abortConnections bool) *stagedReloadHandoff {
	return &stagedReloadHandoff{
		preparedGeneration: candidate,
		oldControlPlane:    active.controlPlane,
		oldCancel:          active.cancel,
		oldConf:            active.conf,
		oldListener:        active.listener,
		newControlPlane:    candidate.controlPlane,
		newCancel:          candidate.cancel,
		newListener:        candidate.listener,
		abortConnections:   abortConnections,
	}
}

var setRunSignalProgress = func(code byte, content string) error {
	return writeSignalProgressFile(SignalProgressFilePath, code, content)
}

var getRunSignalProgress = func() (byte, string, error) {
	return readSignalProgressFile(SignalProgressFilePath)
}

func init() {
	runCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file of dae.(required)")
	runCmd.PersistentFlags().StringVar(&logFile, "logfile", "", "Log file to write. Empty means writing to stdout and stderr.")
	runCmd.PersistentFlags().IntVar(&logFileMaxSize, "logfile-maxsize", 30, "Unit: MB. The maximum size in megabytes of the log file before it gets rotated.")
	runCmd.PersistentFlags().IntVar(&logFileMaxBackups, "logfile-maxbackups", 3, "The maximum number of old log files to retain.")
	runCmd.PersistentFlags().BoolVar(&disableTimestamp, "disable-timestamp", false, "Disable timestamp.")
	runCmd.PersistentFlags().BoolVar(&disablePidFile, "disable-pidfile", false, "Not generate /var/run/dae.pid.")
	runCmd.PersistentFlags().BoolVar(&disableAuthSudo, "disable-sudo", false, "Disable sudo prompt ,may cause startup failure due to insufficient permissions")
	rand.Shuffle(len(CheckNetworkLinks), func(i, j int) {
		CheckNetworkLinks[i], CheckNetworkLinks[j] = CheckNetworkLinks[j], CheckNetworkLinks[i]
	})
}

var (
	cfgFile           string
	logFile           string
	logFileMaxSize    int
	logFileMaxBackups int
	disableTimestamp  bool
	disablePidFile    bool
	disableAuthSudo   bool

	runCmd = &cobra.Command{
		Use:   "run",
		Short: "To run dae in the foreground.",
		Run: func(cmd *cobra.Command, args []string) {
			if cfgFile == "" {
				logrus.Fatalln("Argument \"--config\" or \"-c\" is required but not provided.")
			}
			if disableAuthSudo && os.Geteuid() != 0 {
				logrus.Fatalln("Auto-sudo is disabled and current user is not root.")
			}
			// Require "sudo" if necessary.
			if !disableAuthSudo {
				internal.AutoSu()
			}

			// Read config from --config cfgFile.
			conf, includes, err := readConfig(cfgFile)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"err": err,
				}).Fatalln("Failed to read config")
			}

			var logOpts *lumberjack.Logger
			if logFile != "" {
				logOpts = &lumberjack.Logger{
					Filename:   logFile,
					MaxSize:    logFileMaxSize,
					MaxAge:     0,
					MaxBackups: logFileMaxBackups,
					LocalTime:  true,
					Compress:   true,
				}
			}
			log := logrus.New()
			logger.SetLogger(log, conf.Global.LogLevel, disableTimestamp, logOpts)
			logger.SetLogger(logrus.StandardLogger(), conf.Global.LogLevel, disableTimestamp, logOpts)

			log.Infof("Include config files: [%v]", strings.Join(includes, ", "))
			if err := Run(log, conf, []string{filepath.Dir(cfgFile)}); err != nil {
				log.Fatalln(err)
			}
		},
	}
)

// restorePreviousFreshDatapathGeneration rolls a failed fresh-datapath reload
// back to the previous generation: fresh-handoff rollback, supervisor slot
// restore, and a serve-goroutine restart when the cutover had stopped the old
// listener. step labels the failure context in logs and wrapped errors; the
// caller fails the reload attempt on a non-nil return.
func restorePreviousFreshDatapathGeneration(
	w *reloadWorker,
	sigs <-chan os.Signal,
	runStateChanges chan struct{},
	supervisor *runtimeSupervisor,
	handoff *stagedReloadHandoff,
	step string,
) error {
	recoveredListener, rollbackErr := rollbackFreshDatapathReloadHandoff(w.log, handoff)
	if rollbackErr != nil {
		w.log.WithError(rollbackErr).Errorf("[Reload] Failed to recover previous generation %s", step)
		return fmt.Errorf("recover previous generation %s: %w", step, rollbackErr)
	}
	w.listener = recoveredListener
	if err := supervisor.replaceActive(&runtimeGeneration{
		controlPlane: handoff.oldControlPlane,
		listener:     recoveredListener,
		cancel:       handoff.oldCancel,
		conf:         handoff.oldConf,
	}); err != nil {
		w.log.WithError(err).Errorf("[Reload] Failed to restore supervisor %s", step)
		return fmt.Errorf("restore supervisor %s: %w", step, err)
	}
	if handoff.oldRuntimeStopped {
		if restartErr := restartRecoveredControlPlane(w.log, sigs, runStateChanges, handoff.oldControlPlane, w.listener); restartErr != nil {
			w.log.WithError(restartErr).Errorf("[Reload] Failed to restart previous listener generation %s", step)
			return fmt.Errorf("restart previous generation %s: %w", step, restartErr)
		}
	}
	return nil
}

func Run(log *logrus.Logger, conf *config.Config, externGeoDataDirs []string) (err error) {
	return newRunner(log, conf, externGeoDataDirs).Run()
}

// serveExitTracker records abnormal exits of serve goroutines tagged with
// the control plane each goroutine served, so the run loop can tell an
// abnormal exit of the ACTIVE generation apart from the benign exit of a
// retired or rolled-back one.
type serveExitTracker struct {
	mu    sync.Mutex
	plane *control.ControlPlane
	err   error
}

// report records an abnormal exit. Nil planes and nil errors are ignored:
// a serve goroutine returning nil exited because its generation's context
// was cancelled (planned retirement or shutdown), which is never fatal. A
// later report replaces an earlier one, mirroring "the newest death is the
// one that matters".
func (t *serveExitTracker) report(plane *control.ControlPlane, err error) {
	if plane == nil || err == nil {
		return
	}
	t.mu.Lock()
	t.plane, t.err = plane, err
	t.mu.Unlock()
}

// fatalFor returns the recorded error only when it belongs to the given
// active control plane. The report is consumed either way, so a stale
// record can never misfire against a later generation.
func (t *serveExitTracker) fatalFor(plane *control.ControlPlane) error {
	t.mu.Lock()
	recordedPlane, recordedErr := t.plane, t.err
	t.plane, t.err = nil, nil
	t.mu.Unlock()
	if plane != nil && recordedPlane == plane && recordedErr != nil {
		return recordedErr
	}
	return nil
}

func (r *Runner) Run() (err error) {
	log := r.log
	conf := r.conf
	externGeoDataDirs := r.externGeoDataDirs
	processSessions := control.NewSessionManager(context.Background())
	defer func() {
		err = errors.Join(err, processSessions.Close())
	}()

	var currCancel context.CancelFunc

	// Remove AbortFile at beginning.
	_ = os.Remove(AbortFile)

	// New ControlPlane.
	ctx, cancel := context.WithCancel(context.Background())
	currCancel = cancel
	configureTransparentHugePages(log, conf.Global.DisableTHP)
	configureGcMemoryLimit(log)
	c, err := newControlPlane(ctx, log, nil, nil, conf, externGeoDataDirs, false, false)
	if err != nil {
		cancel()
		return err
	}
	if err = c.AttachSessionManager(processSessions); err != nil {
		cancel()
		_ = c.Close()
		return fmt.Errorf("attach process session manager: %w", err)
	}
	runtimeSupervisor := newRuntimeSupervisor(&runtimeGeneration{
		controlPlane: c,
		cancel:       currCancel,
		conf:         conf,
	})

	// Serve tproxy TCP/UDP server util signals.
	listener, listenErr := listenControlPlaneInDaeNetns(c, conf.Global.TproxyPort)
	if listenErr != nil {
		cancel()
		_ = c.Close()
		return listenErr
	}
	if supervisorErr := runtimeSupervisor.replaceActive(&runtimeGeneration{
		controlPlane: c,
		listener:     listener,
		cancel:       currCancel,
		conf:         conf,
	}); supervisorErr != nil {
		_ = listener.Close()
		cancel()
		_ = c.Close()
		return fmt.Errorf("record initial runtime generation: %w", supervisorErr)
	}

	// w carries the mutable run state that Run's signal loop and the reload
	// worker goroutine exchange; see reloadWorker for the sharing contract.
	w := &reloadWorker{
		externGeoDataDirs: externGeoDataDirs,
		processSessions:   processSessions,
		runtimeSupervisor: runtimeSupervisor,
		log:               log,
		conf:              conf,
		c:                 c,
		currCancel:        currCancel,
		listener:          listener,
	}
	if conf.Global.PprofPort != 0 {
		pprofAddr := fmt.Sprintf("localhost:%d", conf.Global.PprofPort)
		w.pprofServer = &http.Server{Addr: pprofAddr, Handler: nil}
		go func() { _ = w.pprofServer.ListenAndServe() }()
	}
	sigs := make(chan os.Signal, 1)
	// Keep internal wake-ups separate so queued OS signals cannot mask reload handoff notifications.
	runStateChanges := make(chan struct{}, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGILL, syscall.SIGUSR1, syscall.SIGUSR2)

	// Serve-exit reporting lets the main loop distinguish an abnormal exit
	// of the CURRENT generation's serve goroutine from the benign exit of a
	// retired generation's one: if the active generation stops serving while
	// its hooks are still attached, traffic is hijacked with nobody
	// accepting — a silent blackhole. Reports are tagged with the served
	// control plane so only the active generation's death is fatal; a
	// failed candidate's report goes stale once a reload is rolled back.
	var serveExits serveExitTracker
	reportServeExit := serveExits.report

	go func() {
		readyChan := make(chan bool, 1)
		go func() {
			if <-readyChan {
				_ = sdnotify.Ready()
				if !disablePidFile {
					_ = os.WriteFile(PidFilePath, []byte(strconv.Itoa(os.Getpid())), 0o644)
				}
				_ = setRunSignalProgress(consts.ReloadDone, "")
			} else {
				w.log.Warn("Initialization failed; not signaling readiness to supervisor")
			}
		}()
		defer func() {
			select {
			case readyChan <- false:
			default:
			}
		}()
		if runErr := withDaeNetnsRequiredFunc("serve in dae netns", func() error {
			if serveErr := serveControlPlaneFunc(w.c, readyChan, w.listener); serveErr != nil {
				w.log.Errorln("Serve:", serveErr)
				return serveErr
			}
			return nil
		}); runErr != nil {
			w.log.Errorln("GetDaeNetns.With:", runErr)
			reportServeExit(w.c, runErr)
		}
		notifyRunStateChange(runStateChanges)
	}()

	reloadReqs := make(chan reloadRequest, 1)
	reloadManager := newReloadManager(reloadReqs, runStateChanges, sigs)
	w.reloadManager = reloadManager
	w.runStateChanges = runStateChanges
	fastExit := false
	var fatalRunErr error
	failRun := func(err error) {
		fastExit = true
		fatalRunErr = errors.Join(fatalRunErr, err)
		reloadManager.setReloadError(fatalRunErr)
		_ = setRunSignalProgress(consts.ReloadError, fatalRunErr.Error())
	}

	go w.run()

loop:
	for {
		select {
		case sig := <-sigs:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
				w.log.Infof("Received termination signal: %v", sig.String())
				fastExit = true
				break loop
			case syscall.SIGUSR2:
				reloadManager.queueReloadRequest(w.log, reloadRequest{
					isSuspend:       true,
					requestedAt:     time.Now(),
					requestedAtMono: monotonicNowNano(),
				})
			case syscall.SIGUSR1:
				reloadManager.queueReloadRequest(w.log, reloadRequest{
					isSuspend:       false,
					requestedAt:     time.Now(),
					requestedAtMono: monotonicNowNano(),
				})
			case syscall.SIGHUP:
				// Ignore.
				continue
			default:
				w.log.Infof("Received signal: %v", sig.String())
			}
		case <-runStateChanges:
			switch {
			case reloadManager.reloading.Load():
				if w.listener == nil {
					w.log.Infoln("[Reload] Re-listening after reload")
					readyChan := make(chan bool, 1)
					go func() {
						defer func() {
							select {
							case readyChan <- false:
							default:
							}
						}()
						// Keep all errors local: this goroutine can outlive the
						// readiness wait below and must never write Run's named
						// return, which the main loop reads on every exit path.
						listener, listenErr := listenControlPlaneInDaeNetns(w.c, w.conf.Global.TproxyPort)
						if listenErr != nil {
							w.log.Errorln("Listen:", listenErr)
							reportServeExit(w.c, fmt.Errorf("re-listen: %w", listenErr))
						} else {
							w.listener = listener
							if serveErr := serveControlPlaneFunc(w.c, readyChan, listener); serveErr != nil {
								w.log.Errorln("Serve:", serveErr)
								reportServeExit(w.c, serveErr)
							}
						}
						notifyRunStateChange(runStateChanges)
					}()
					waitResult, termSig := waitReloadReadyOrSignal(w.log, sigs, readyChan, reloadReadyTimeout)
					if waitResult == reloadReadyWaitSignal && termSig != nil {
						w.log.Infof("Received termination signal while waiting for reload readiness: %v", termSig.String())
						fastExit = true
						break loop
					}
					if waitResult != reloadReadyWaitReady {
						reloadErr := fmt.Errorf("reload listener failed before becoming ready")
						if waitResult == reloadReadyWaitTimeout {
							reloadErr = fmt.Errorf("reload listener timed out after %v", reloadReadyTimeout)
						}
						reloadManager.setReloadError(reloadErr)
						_ = sdnotify.Ready()
						_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
						w.log.WithError(reloadErr).Errorln("[Reload] Reload listener failed before becoming ready")
						if !canRecoverReloadReadinessFailure(waitResult) {
							failRun(reloadErr)
							break loop
						}
						reloadManager.finishReloadFailure()
						continue
					}
					_ = sdnotify.Ready()
					if reloadErr := reloadManager.reloadError(); reloadErr == nil {
						_ = setRunSignalProgress(consts.ReloadDone, "OK")
					} else {
						_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
					}
					w.log.Infoln("[Reload] Finished")
					reloadManager.finishReloadSuccess()
					continue
				}
				// Serve.
				reloadManager.reloading.Store(false)
				w.log.Infoln("[Reload] Serve")
				handoff := reloadManager.currentPendingStagedHandoff()
				serveControlPlane := w.c
				serveListener := w.listener
				serveConf := w.conf
				if handoff != nil {
					if handoff.preparedGeneration == nil || handoff.preparedGeneration.controlPlane == nil || handoff.preparedGeneration.listener == nil || handoff.preparedGeneration.conf == nil {
						reloadErr := fmt.Errorf("staged reload is missing its prepared generation")
						reloadManager.setReloadError(reloadErr)
						w.log.WithError(reloadErr).Errorln("[Reload] Failed to serve staged reload candidate")
						if candidate := handoff.preparedGeneration; candidate != nil {
							runtimeSupervisor.rollbackPrepared(candidate)
							if handoff.newControlPlane == nil {
								handoff.newControlPlane = candidate.controlPlane
							}
							if handoff.newListener == nil {
								handoff.newListener = candidate.listener
							}
							if handoff.newCancel == nil {
								handoff.newCancel = candidate.cancel
							}
						}
						if handoff.freshDatapath && handoff.freshCutoverStarted {
							if restoreErr := restorePreviousFreshDatapathGeneration(w, sigs, runStateChanges, runtimeSupervisor, handoff, "from malformed fresh handoff"); restoreErr != nil {
								failRun(errors.Join(reloadErr, restoreErr))
								break loop
							}
						} else {
							if restoreErr := restoreStagedReloadHandoff(w.log, handoff); restoreErr != nil {
								reloadManager.setReloadError(errors.Join(reloadErr, restoreErr))
								w.log.WithError(restoreErr).Errorln("[Reload] Failed to recover previous generation from malformed staged handoff")
								reloadManager.clearPendingStagedHandoff()
								failRun(errors.Join(reloadErr, fmt.Errorf("recover malformed staged handoff: %w", restoreErr)))
								break loop
							}
						}
						reloadManager.clearPendingStagedHandoff()
						reloadManager.failPublishedReloadAttempt(reloadErr)
						continue
					}
					serveControlPlane = handoff.preparedGeneration.controlPlane
					serveListener = handoff.preparedGeneration.listener
					serveConf = handoff.preparedGeneration.conf
				}
				if handoff != nil && handoff.freshDatapath {
					if cutoverErr := prepareFreshDatapathCutover(w.log, handoff); cutoverErr != nil {
						reloadErr := fmt.Errorf("prepare fresh datapath cutover: %w", cutoverErr)
						reloadManager.setReloadError(reloadErr)
						_ = sdnotify.Ready()
						_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
						w.log.WithError(reloadErr).Errorln("[Reload] Fresh datapath cutover failed; restoring previous generation")

						runtimeSupervisor.rollbackPrepared(handoff.preparedGeneration)
						if restoreErr := restorePreviousFreshDatapathGeneration(w, sigs, runStateChanges, runtimeSupervisor, handoff, "after cutover error"); restoreErr != nil {
							failRun(errors.Join(reloadErr, restoreErr))
							break loop
						}
						reloadManager.clearPendingStagedHandoff()
						reloadManager.finishReloadFailure()
						continue
					}
				} else if handoff != nil && handoff.preparedDNSHandoff {
					reloadManager.installPreparedDNSHandoffHooks(w.log, serveControlPlane, serveConf)
				}
				if handoff != nil && handoff.sharedBpfHandoff && !handoff.freshDatapath && !handoff.oldConnectivityPaused {
					// The prepared generation already suppresses its own health-map
					// writes. Pause the active generation before CommitPreparedDatapath
					// publishes shared BPF state so stale health probes cannot
					// overwrite the candidate's connectivity state.
					if handoff.oldControlPlane != nil {
						handoff.oldControlPlane.PauseOutboundConnectivityUpdates()
						handoff.oldConnectivityPaused = true
					}
				}
				readyChan := make(chan bool, 1)
				go func() {
					defer func() {
						select {
						case readyChan <- false:
						default:
						}
					}()
					if err := serveControlPlaneFunc(serveControlPlane, readyChan, serveListener); err != nil {
						w.log.Errorln("ListenAndServe:", err)
						reportServeExit(serveControlPlane, err)
					}
					notifyRunStateChange(runStateChanges)
				}()
				waitResult, termSig := waitReloadReadyOrSignal(w.log, sigs, readyChan, reloadReadyTimeout)
				if waitResult == reloadReadyWaitSignal && termSig != nil {
					w.log.Infof("Received termination signal while waiting for reload readiness: %v", termSig.String())
					fastExit = true
					break loop
				}
				if waitResult != reloadReadyWaitReady {
					reloadErr := fmt.Errorf("reload serve failed before becoming ready")
					if !canRecoverReloadReadinessFailure(waitResult) {
						reloadErr = fmt.Errorf("reload serve timed out after %v", reloadReadyTimeout)
					}
					reloadManager.setReloadError(reloadErr)
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
					w.log.WithError(reloadErr).Errorln("[Reload] Reload serve failed before becoming ready")
					if waitResult == reloadReadyWaitTimeout {
						// Serve may still be mutating shared BPF state. Do not race a
						// rollback against a late commit; terminate and let the service
						// manager start from a clean datapath instead.
						failRun(reloadErr)
						break loop
					}
					if handoff := reloadManager.currentPendingStagedHandoff(); handoff != nil {
						runtimeSupervisor.rollbackPrepared(handoff.preparedGeneration)
						if handoff.freshDatapath {
							if restoreErr := restorePreviousFreshDatapathGeneration(w, sigs, runStateChanges, runtimeSupervisor, handoff, "after fresh datapath handoff failure"); restoreErr != nil {
								failRun(errors.Join(reloadErr, restoreErr))
								break loop
							}
						} else {
							reloadManager.clearPendingStagedHandoff()
							if restoreErr := restoreStagedReloadHandoff(w.log, handoff); restoreErr != nil {
								reloadManager.setReloadError(errors.Join(reloadErr, restoreErr))
								w.log.WithError(restoreErr).Errorln("[Reload] Failed to recover previous generation after staged handoff failure")
								failRun(errors.Join(reloadErr, fmt.Errorf("recover previous generation after staged handoff failure: %w", restoreErr)))
								break loop
							}
							w.log.Warnln("[Reload] Restored previous listener generation after staged handoff failure")
						}
					}
					reloadManager.clearPendingStagedHandoff()
					reloadManager.finishReloadFailure()
					continue
				}
				dnsHandoffActive := reloadManager.pendingDNSHandoffActive(serveControlPlane)
				if handoff := reloadManager.currentPendingStagedHandoff(); handoff != nil {
					var publishErr error
					if !handoff.tcHookHandoffPrepared {
						publishErr = handoff.newControlPlane.PrepareTCHookHandoff(handoff.oldControlPlane)
						if publishErr == nil {
							handoff.tcHookHandoffPrepared = true
						}
					}
					if handoff.freshDatapath && !handoff.provisionalOwner {
						if publishErr == nil {
							publishErr = handoff.newControlPlane.RegisterProvisionalRoutingEpochExecutionOwner()
						}
						if publishErr == nil {
							handoff.provisionalOwner = true
						}
					}
					if !handoff.hookFlipCommitted {
						if publishErr == nil {
							publishErr = handoff.newControlPlane.CommitPreparedBpfHookFlip()
						}
						if publishErr == nil {
							handoff.hookFlipCommitted = true
						}
					}
					if !handoff.tcHookSetAdopted {
						if publishErr == nil {
							publishErr = handoff.newControlPlane.AdoptPreparedTCHookSet(handoff.oldControlPlane)
						}
						if publishErr == nil {
							handoff.tcHookSetAdopted = true
						}
					}
					if handoff.freshDatapath && !handoff.flowDatapathAdopted {
						if publishErr == nil {
							publishErr = handoff.newControlPlane.AdoptProcessFlowDatapath(handoff.oldControlPlane)
						}
						if publishErr == nil {
							handoff.flowDatapathAdopted = true
						}
					}
					var retiringGeneration *runtimeGeneration
					if publishErr == nil {
						retiringGeneration, publishErr = runtimeSupervisor.publishPrepared(handoff.preparedGeneration)
					}
					if publishErr == nil && handoff.provisionalOwner {
						handoff.newControlPlane.UnregisterProvisionalRoutingEpochExecutionOwner()
						handoff.provisionalOwner = false
					}
					if publishErr != nil {
						reloadErr := fmt.Errorf("publish staged reload candidate: %w", publishErr)
						reloadManager.setReloadError(reloadErr)
						w.log.WithError(reloadErr).Errorln("[Reload] Failed to publish staged reload candidate; keeping current generation active")
						runtimeSupervisor.rollbackPrepared(handoff.preparedGeneration)
						if handoff.freshDatapath {
							if restoreErr := restorePreviousFreshDatapathGeneration(w, sigs, runStateChanges, runtimeSupervisor, handoff, "after publish error"); restoreErr != nil {
								failRun(errors.Join(reloadErr, restoreErr))
								break loop
							}
						} else {
							if restoreErr := restoreStagedReloadHandoff(w.log, handoff); restoreErr != nil {
								reloadManager.setReloadError(errors.Join(reloadErr, restoreErr))
								w.log.WithError(restoreErr).Errorln("[Reload] Failed to recover previous generation after publish error")
								reloadManager.clearPendingStagedHandoff()
								failRun(errors.Join(reloadErr, fmt.Errorf("recover previous generation after publish error: %w", restoreErr)))
								break loop
							}
						}
						reloadManager.clearPendingStagedHandoff()
						reloadManager.failPublishedReloadAttempt(reloadErr)
						continue
					}

					if err := handoff.newControlPlane.FinalizePreparedTCHooks(); err != nil {
						finalizeErr := fmt.Errorf("finalize published TC HookSet: %w", err)
						reloadManager.setReloadError(finalizeErr)
						failRun(finalizeErr)
						break loop
					}
					handoff.tcHookHandoffPrepared = false
					handoff.tcHookSetAdopted = false
					handoff.hookFlipCommitted = false

					oldListener := handoff.oldListener
					oldC := handoff.oldControlPlane
					oldCancel := handoff.oldCancel
					abortConnections := handoff.abortConnections
					if oldC != nil && !handoff.freshDatapath && !handoff.bpfTransferred {
						bpf := oldC.EjectBpf()
						serveControlPlane.InjectBpf(bpf)
					}
					if handoff.sharedBpfHandoff {
						// The supervisor now owns the candidate as active. Publish its
						// current health snapshot only after this point; the old
						// generation remains paused until retirement closes it.
						serveControlPlane.ResumeOutboundConnectivityUpdates()
					}
					if oldC != nil {
						if detachErr := oldC.DetachBpfHooks(); detachErr != nil {
							w.log.WithError(detachErr).Warnln("[Reload] Failed to detach previous datapath hooks after publish; retrying")
							if retryErr := oldC.DetachBpfHooks(); retryErr != nil {
								detachFatalErr := errors.Join(
									fmt.Errorf("detach previous datapath hooks: %w", retryErr),
									fmt.Errorf("initial detach previous datapath hooks: %w", detachErr),
								)
								reloadManager.setReloadError(detachFatalErr)
								w.log.WithError(retryErr).Errorln("[Reload] Previous datapath hooks remain attached after publish")
								failRun(detachFatalErr)
								break loop
							}
						}
					}
					w.c = handoff.preparedGeneration.controlPlane
					w.currCancel = handoff.preparedGeneration.cancel
					w.conf = handoff.preparedGeneration.conf
					w.listener = handoff.preparedGeneration.listener
					reloadManager.clearPendingStagedHandoff()

					if oldListener != nil {
						if err := oldListener.Close(); err != nil {
							w.log.WithError(err).Warnln("[Reload] Failed to close previous listener generation")
						}
					}
					handoff.oldRuntimeStopped = true

					if oldC != nil {
						reloadManager.startControlPlaneRetirement(w.log, oldC, w.c, oldCancel, abortConnections, runtimeSupervisor, retiringGeneration)
					}
				}
				_ = sdnotify.Ready()
				if reloadErr := reloadManager.reloadError(); reloadErr == nil {
					_ = setRunSignalProgress(consts.ReloadDone, "OK")
				} else {
					_ = setRunSignalProgress(consts.ReloadError, reloadErr.Error())
				}
				w.log.Infoln("[Reload] Finished")
				reloadManager.finishReloadSuccess()
				if dnsHandoffActive && w.log.IsLevelEnabled(logrus.DebugLevel) {
					w.log.Debugln("[Reload] Shared DNS controller handoff remains available while old generation drains")
				}
			case w.listener == nil:
				// Listening error.
				w.log.Errorln("[Critical] Listener failed; exiting")
				break loop
			default:
				// Not reloading and the listener exists: check whether the
				// active generation's serve goroutine died. Without this the
				// process would keep running with hooks attached while
				// nobody accepts — a silent blackhole until the next reload.
				// Reports from retired or rolled-back generations never
				// match w.c; consume them here so a stale report cannot
				// misfire later.
				if err := serveExits.fatalFor(w.c); err != nil {
					w.log.WithError(err).Errorln("[Critical] Serve exited for the active generation; exiting")
					failRun(fmt.Errorf("serve exited for the active generation: %w", err))
					break loop
				}
			}
		}
	}

	defer func() {
		_ = sdnotify.Stopping()
		if w.pprofServer != nil {
			w.log.Infoln("Shutting down pprof server")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = w.pprofServer.Shutdown(ctx)
			cancel()
		}
		_ = os.Remove(PidFilePath)
	}()

	// Stop accepting new ingress immediately so shutdown does not continue to
	// create fresh UDP/TCP work while the control plane is being torn down.
	shutdownHandoff := buildRunShutdownHandoff(reloadManager, runtimeSupervisor, &runtimeGeneration{
		controlPlane: w.c,
		listener:     w.listener,
		cancel:       w.currCancel,
		conf:         w.conf,
	}, fastExit)
	shutdownErr := shutdownAfterSignalWithHandoff(w.log, w.listener, w.c, control.GetDaeNetns(), fastExit, shutdownHandoff)
	return errors.Join(fatalRunErr, shutdownErr)
}

func init() {
	rootCmd.AddCommand(runCmd)
}
