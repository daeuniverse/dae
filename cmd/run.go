/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"gopkg.in/natefinch/lumberjack.v2"

	_ "net/http/pprof"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/common/subscription"
	"github.com/daeuniverse/dae/component/daedns"
	outbounddialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/logger"
	"github.com/mohae/deepcopy"
	"github.com/okzk/sdnotify"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
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
	newListener     signalShutdownListener
	newControlPlane signalShutdownControlPlane
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
	oldControlPlane  *control.ControlPlane
	oldCancel        context.CancelFunc
	oldConf          *config.Config
	oldListener      *control.Listener
	newControlPlane  *control.ControlPlane
	newCancel        context.CancelFunc
	newListener      *control.Listener
	abortConnections bool
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

var setRunSignalProgress = func(code byte, content string) error {
	return writeSignalProgressFile(SignalProgressFilePath, code, content)
}

func restoreRejectedReloadProgress(reloadActive *atomic.Bool, forceProcessing bool) {
	if forceProcessing || (reloadActive != nil && reloadActive.Load()) {
		_ = setRunSignalProgress(consts.ReloadBusy, reloadBusyActiveMessage)
		return
	}
	_ = setRunSignalProgress(consts.ReloadBusy, reloadBusyRetiringMessage)
}

func clearRejectedReloadProgress() {
	code, _, err := readSignalProgressFile(SignalProgressFilePath)
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

func releaseReloadPendingAfterRetirement(flag *atomic.Bool, retirementDone <-chan struct{}) {
	if flag == nil {
		endReloadProxyFailureSuppression()
		return
	}
	if retirementDone == nil {
		clearReloadPending(flag)
		return
	}
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

func monotonicNowNano() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Nano())
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

func Run(log *logrus.Logger, conf *config.Config, externGeoDataDirs []string) (err error) {
	var currCancel context.CancelFunc

	// Remove AbortFile at beginning.
	_ = os.Remove(AbortFile)

	// New ControlPlane.
	ctx, cancel := context.WithCancel(context.Background())
	currCancel = cancel
	c, err := newControlPlane(ctx, log, nil, nil, conf, externGeoDataDirs)
	if err != nil {
		cancel()
		return err
	}

	var pprofServer *http.Server
	if conf.Global.PprofPort != 0 {
		pprofAddr := fmt.Sprintf("localhost:%d", conf.Global.PprofPort)
		pprofServer = &http.Server{Addr: pprofAddr, Handler: nil}
		go func() { _ = pprofServer.ListenAndServe() }()
	}

	// Serve tproxy TCP/UDP server util signals.
	var listener *control.Listener
	sigs := make(chan os.Signal, 1)
	// Keep internal wake-ups separate so queued OS signals cannot mask reload handoff notifications.
	runStateChanges := make(chan struct{}, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGILL, syscall.SIGUSR1, syscall.SIGUSR2)

	go func() {
		readyChan := make(chan bool, 1)
		go func() {
			if <-readyChan {
				_ = sdnotify.Ready()
				if !disablePidFile {
					_ = os.WriteFile(PidFilePath, []byte(strconv.Itoa(os.Getpid())), 0644)
				}
				_ = setRunSignalProgress(consts.ReloadDone, "")
			} else {
				log.Warn("Initialization failed; not signaling readiness to supervisor")
			}
		}()
		defer func() {
			select {
			case readyChan <- false:
			default:
			}
		}()
		if runErr := control.GetDaeNetns().WithRequired("listen and serve in dae netns", func() error {
			if listener, err = c.Listen(conf.Global.TproxyPort); err != nil {
				log.Errorln("Listen:", err)
				return err
			}
			if err = c.Serve(readyChan, listener); err != nil {
				log.Errorln("Serve:", err)
			}
			return err
		}); runErr != nil {
			log.Errorln("GetDaeNetns.With:", runErr)
		}
		notifyRunStateChange(runStateChanges)
	}()

	reloadReqs := make(chan reloadRequest, 1)

	var reloading atomic.Bool
	var reloadActive atomic.Bool
	var reloadPending atomic.Bool
	reloadingErr := error(nil)
	var lastRetirementCancel context.CancelFunc
	var lastRetirementMu sync.Mutex
	var pendingStagedHandoff *stagedReloadHandoff
	var pendingRetirementDone <-chan struct{}
	var pendingReloadRequestedAt time.Time
	var pendingReloadRequestedAtMono uint64
	fastExit := false

	go func() {
		for req := range reloadReqs {
			reloadActive.Store(true)
			reloadStartedAt := req.requestedAt
			reloadStartedAtMono := req.requestedAtMono
			if reloadStartedAt.IsZero() {
				reloadStartedAt = time.Now()
			}
			// Coalesce rapid reload requests: skip intermediate requests if multiple are queued
			// while we were building the previous one. Only the latest state matters.
		coalesce:
			for {
				select {
				case nextReq := <-reloadReqs:
					req = nextReq
					reloadStartedAt = req.requestedAt
					reloadStartedAtMono = req.requestedAtMono
					if reloadStartedAt.IsZero() {
						reloadStartedAt = time.Now()
					}
					continue
				default:
					break coalesce
				}
			}

			if req.isSuspend {
				log.Warnln("[Reload] Received suspend signal; prepare to suspend")
			} else {
				log.Warnln("[Reload] Received reload signal; prepare to reload")
			}
			_ = sdnotify.Reloading()
			_ = setRunSignalProgress(consts.ReloadProcessing, "")
			reloadingErr = nil
			resetReloadProxyRuntimeState()

			// Load new config.
			abortConnections := os.Remove(AbortFile) == nil
			log.Warnln("[Reload] Load new config")
			var newConf *config.Config
			if req.isSuspend {
				newConf, err = emptyConfig()
				if err != nil {
					log.WithFields(logrus.Fields{
						"err": err,
					}).Errorln("[Reload] Failed to reload")
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, err.Error())
					reloadActive.Store(false)
					clearReloadPending(&reloadPending)
					continue
				}
				newConf.Global = deepcopy.Copy(conf.Global).(config.Global)
				newConf.Global.WanInterface = nil
				newConf.Global.LanInterface = nil
				newConf.Global.LogLevel = "warning"
			} else {
				var includes []string
				newConf, includes, err = readConfig(cfgFile)
				if err != nil {
					log.WithFields(logrus.Fields{
						"err": err,
					}).Errorln("[Reload] Failed to reload")
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, err.Error())
					reloadActive.Store(false)
					clearReloadPending(&reloadPending)
					continue
				}
				log.Infof("Include config files: [%v]", strings.Join(includes, ", "))
			}
			// New logger.
			oldLogOutput := log.Out
			log = logrus.New()
			logger.SetLogger(log, newConf.Global.LogLevel, disableTimestamp, nil)
			logger.SetLogger(logrus.StandardLogger(), newConf.Global.LogLevel, disableTimestamp, nil)
			log.SetOutput(oldLogOutput) // NOTE: Restore log output after creating new logger during reload.
			logrus.SetOutput(oldLogOutput)

			portChanged := conf.Global.TproxyPort != newConf.Global.TproxyPort
			stagedHotHandoff := !portChanged && listener != nil

			// New control plane.
			obj := c.PeekBpf()
			if !stagedHotHandoff {
				obj = c.EjectBpf()
			}
			if portChanged {
				log.Warnf("[Reload] Tproxy port changed from %d to %d; will perform a full reload of eBPF programs", conf.Global.TproxyPort, newConf.Global.TproxyPort)
				_ = obj.Close()
				obj = nil
			}

			var dnsCache map[string]*control.DnsCache
			if conf.Dns.IpVersionPrefer == newConf.Dns.IpVersionPrefer {
				// Only keep dns cache when ip version preference not change.
				dnsCache = c.CloneDnsCache()
			}
			rollbackDNSCache := dnsCache
			var stagedListener *control.Listener

			if stagedHotHandoff {
				log.Warnln("[Reload] Prepare staged same-port handoff")
				ctx, cancel := context.WithTimeout(context.Background(), reloadPrepareTimeout)
				newC, prepareErr := newPreparedControlPlane(ctx, log, obj, dnsCache, newConf, externGeoDataDirs)
				dnsCache = nil
				if prepareErr != nil {
					reloadingErr = wrapReloadTimeoutError("prepare staged reload", prepareErr, reloadPrepareTimeout)
					cancel()
					log.WithError(reloadingErr).Errorln("[Reload] Failed to prepare staged reload; keeping current generation active")
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, reloadingErr.Error())
					reloadActive.Store(false)
					clearReloadPending(&reloadPending)
					continue
				}

				stagedListener, listenErr := listener.Clone()
				if listenErr != nil {
					reloadingErr = fmt.Errorf("clone listener: %w", listenErr)
					cancel()
					if closeErr := newC.Close(); closeErr != nil {
						log.WithError(closeErr).Warnln("[Reload] Failed to close prepared staged generation")
					}
					log.WithError(reloadingErr).Errorln("[Reload] Failed to stage listener; keeping current generation active")
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, reloadingErr.Error())
					reloadActive.Store(false)
					clearReloadPending(&reloadPending)
					continue
				}

				oldC := c
				oldCancel := currCancel
				oldConf := conf
				oldListener := listener

				newC.InheritDialerHealthFrom(oldC)
				c = newC
				currCancel = cancel
				conf = newConf
				listener = stagedListener
				pendingStagedHandoff = &stagedReloadHandoff{
					oldControlPlane:  oldC,
					oldCancel:        oldCancel,
					oldConf:          oldConf,
					oldListener:      oldListener,
					newControlPlane:  newC,
					newCancel:        cancel,
					newListener:      stagedListener,
					abortConnections: abortConnections,
				}
				pendingReloadRequestedAt = reloadStartedAt
				pendingReloadRequestedAtMono = reloadStartedAtMono
				beginReloadHandoff(&reloading, runStateChanges)
				notifyRunStateChange(runStateChanges)
				continue
			}

			// Stop old DNS listener before creating new one to avoid port conflicts
			if err := c.StopDNSListener(); err != nil {
				log.Warnf("[Reload] Failed to stop old DNS listener: %v", err)
			}

			log.Warnln("[Reload] Load new control plane")
			ctx, cancel := context.WithTimeout(context.Background(), reloadPrepareTimeout)
			newC, err := newControlPlane(ctx, log, obj, dnsCache, newConf, externGeoDataDirs)
			dnsCache = nil // Allow previous generation's clone to be GC'd.

			var newCancel context.CancelFunc
			if err != nil {
				reloadingErr = wrapReloadTimeoutError("build new control plane", err, reloadPrepareTimeout)
				log.WithFields(logrus.Fields{
					"err": err,
				}).Errorln("[Reload] Failed to reload; try to roll back configuration")
				cancel()

				// Load last config back.
				if portChanged {
					log.Warnln("[Reload] Port already changed; attempting rollback with fresh eBPF objects")
					obj = nil
				}
				ctx, cancel = context.WithTimeout(context.Background(), reloadPrepareTimeout)
				newC, err = newControlPlane(ctx, log, obj, rollbackDNSCache, conf, externGeoDataDirs)
				err = wrapReloadTimeoutError("rollback control plane", err, reloadPrepareTimeout)
				if err != nil {
					_ = sdnotify.Stopping()
					if obj != nil && !stagedHotHandoff {
						_ = obj.Close()
					}
					_ = c.Close()
					cancel()
					log.WithFields(logrus.Fields{
						"err": err,
					}).Fatalln("[Reload] Failed to roll back configuration")
				}
				newConf = conf
				newCancel = cancel
				log.Errorln("[Reload] Last reload failed; rolled back configuration")
			} else {
				newCancel = cancel
				log.Warnln("[Reload] Prepared new control plane")
			}

			if stagedListener == nil {
				stagedListener, err = newC.Listen(newConf.Global.TproxyPort)
				if err != nil {
					reloadingErr = fmt.Errorf("prepare new listener: %w", err)
					if newCancel != nil {
						newCancel()
					}
					if closeErr := newC.Close(); closeErr != nil {
						log.WithError(closeErr).Warnln("[Reload] Failed to clean up after listener preparation error")
					}
					if obj != nil && !stagedHotHandoff {
						c.InjectBpf(obj)
					}
					if restartErr := c.RestartDNSListener(); restartErr != nil {
						log.WithError(restartErr).Warnln("[Reload] Failed to restart previous DNS listener after reload preparation error")
					}
					log.WithError(reloadingErr).Errorln("[Reload] Failed to prepare listener; keeping current generation active")
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, reloadingErr.Error())
					reloadActive.Store(false)
					clearReloadPending(&reloadPending)
					continue
				}
			}

			// Non-staged paths transfer BPF/LPM ownership immediately because the
			// old generation is no longer able to keep serving.
			if !stagedHotHandoff {
				newC.InjectBpf(obj)
				if c != nil {
					newC.InheritLpmIndices(c.EjectLpmIndices())
				}
			}

			var oldListener *control.Listener
			if listener != nil {
				oldListener = listener
			}

			// Prepare new context.
			oldC := c
			oldCancel := currCancel
			oldConf := conf

			newC.InheritDialerHealthFrom(oldC)
			c = newC
			currCancel = newCancel
			conf = newConf
			listener = stagedListener
			if stagedHotHandoff {
				pendingStagedHandoff = &stagedReloadHandoff{
					oldControlPlane:  oldC,
					oldCancel:        oldCancel,
					oldConf:          oldConf,
					oldListener:      oldListener,
					newControlPlane:  newC,
					newCancel:        newCancel,
					newListener:      stagedListener,
					abortConnections: abortConnections,
				}
			} else {
				pendingStagedHandoff = nil
			}
			pendingRetirementDone = nil
			pendingReloadRequestedAt = reloadStartedAt
			pendingReloadRequestedAtMono = reloadStartedAtMono
			beginReloadHandoff(&reloading, runStateChanges)

			// Ready to close.
			if oldC != nil && pendingStagedHandoff == nil {
				if oldListener != nil {
					if err := oldListener.Close(); err != nil {
						log.WithError(err).Warnln("[Reload] Failed to close previous listener generation")
					}
				}
				// Generational Coalescing: If there is already a generation waiting for retirement,
				// cancel its grace period and force it to close immediately to prevent heap stacking.
				lastRetirementMu.Lock()
				if lastRetirementCancel != nil {
					lastRetirementCancel()
				}
				retireCtx, retireCancel := context.WithCancel(context.Background())
				lastRetirementCancel = retireCancel
				lastRetirementMu.Unlock()

				log.Warnln("[Reload] Retiring old control plane")
				retirementDone := make(chan struct{})
				pendingRetirementDone = retirementDone
				drainBudget := remainingReloadRetirementBudget(pendingReloadRequestedAt, reloadTotalSwitchBudget)
				staleBeforeNs := pendingReloadRequestedAtMono
				successor := newC
				go func(
					ctx context.Context,
					c *control.ControlPlane,
					successor *control.ControlPlane,
					cancel context.CancelFunc,
					abort bool,
					maxDrain time.Duration,
					staleBeforeNs uint64,
					done chan struct{},
				) {
					defer close(done)
					switch waitForControlPlaneDrain(log, ctx, c, maxDrain, controlPlaneRetirementLogEvery) {
					case controlPlaneDrainIdle:
						log.Infoln("[Reload] Old control plane drained active sessions; retiring immediately")
					case controlPlaneDrainCanceled:
						log.Warnln("[Reload] New generation ready; accelerating old generation retirement")
					case controlPlaneDrainTimeout:
						log.WithField("active_sessions", c.ActiveSessionCount()).
							Warnln("[Reload] Old control plane drain timed out; forcing retirement")
					}

					if abort {
						_ = c.AbortConnections()
					}

					// Crucial: Cancel the generation's workers before closing structural resources.
					if cancel != nil {
						cancel()
					}

					if closeErr := c.Close(); closeErr != nil {
						log.WithError(closeErr).Warnln("[Reload] Old control plane close did not finish cleanly")
					}
					if successor != nil {
						successor.RunReloadRetirementCleanup(staleBeforeNs)
					}
					log.Warnln("[Reload] Retired old control plane")
				}(retireCtx, oldC, successor, oldCancel, abortConnections, drainBudget, staleBeforeNs, retirementDone)
			}

			if pprofServer != nil {
				pprofCtx, pprofCancel := context.WithTimeout(context.Background(), 2*time.Second)
				_ = pprofServer.Shutdown(pprofCtx)
				pprofCancel()
				pprofServer = nil
			}
			if newConf.Global.PprofPort != 0 {
				pprofAddr := fmt.Sprintf("localhost:%d", conf.Global.PprofPort)
				pprofServer = &http.Server{Addr: pprofAddr, Handler: nil}
				go func() { _ = pprofServer.ListenAndServe() }()
			}

			notifyRunStateChange(runStateChanges)

		}
	}()

loop:
	for {
		select {
		case sig := <-sigs:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL:
				log.Infof("Received termination signal: %v", sig.String())
				fastExit = true
				break loop
			case syscall.SIGUSR2:
				tryQueueReloadRequest(log, reloadReqs, &reloadActive, &reloadPending, reloadRequest{
					isSuspend:       true,
					requestedAt:     time.Now(),
					requestedAtMono: monotonicNowNano(),
				})
			case syscall.SIGUSR1:
				tryQueueReloadRequest(log, reloadReqs, &reloadActive, &reloadPending, reloadRequest{
					isSuspend:       false,
					requestedAt:     time.Now(),
					requestedAtMono: monotonicNowNano(),
				})
			case syscall.SIGHUP:
				// Ignore.
				continue
			default:
				log.Infof("Received signal: %v", sig.String())
			}
		case <-runStateChanges:
			if reloading.Load() {
				if listener == nil {
					log.Warnln("[Reload] Re-listening after reload")
					readyChan := make(chan bool, 1)
					go func() {
						defer func() {
							select {
							case readyChan <- false:
							default:
							}
						}()
						if runErr := control.GetDaeNetns().WithRequired("listen and serve in dae netns", func() error {
							if listener, err = c.Listen(conf.Global.TproxyPort); err != nil {
								log.Errorln("Listen:", err)
								return err
							}
							if err = c.Serve(readyChan, listener); err != nil {
								log.Errorln("Serve:", err)
							}
							return err
						}); runErr != nil {
							log.Errorln("GetDaeNetns.With:", runErr)
						}
						notifyRunStateChange(runStateChanges)
					}()
					waitResult, termSig := waitReloadReadyOrSignal(log, sigs, readyChan, reloadReadyTimeout)
					if waitResult == reloadReadyWaitSignal && termSig != nil {
						log.Infof("Received termination signal while waiting for reload readiness: %v", termSig.String())
						fastExit = true
						break loop
					}
					if waitResult != reloadReadyWaitReady {
						reloadingErr = fmt.Errorf("reload listener failed before becoming ready")
						if waitResult == reloadReadyWaitTimeout {
							reloadingErr = fmt.Errorf("reload listener timed out after %v", reloadReadyTimeout)
						}
						_ = sdnotify.Ready()
						_ = setRunSignalProgress(consts.ReloadError, reloadingErr.Error())
						log.WithError(reloadingErr).Errorln("[Reload] Reload listener failed before becoming ready")
						reloading.Store(false)
						reloadActive.Store(false)
						clearReloadPending(&reloadPending)
						continue
					}
					_ = sdnotify.Ready()
					if reloadingErr == nil {
						_ = setRunSignalProgress(consts.ReloadDone, "OK")
					} else {
						_ = setRunSignalProgress(consts.ReloadError, reloadingErr.Error())
					}
					log.Warnln("[Reload] Finished")
					reloading.Store(false)
					reloadActive.Store(false)
					releaseReloadPendingAfterRetirement(&reloadPending, pendingRetirementDone)
					pendingRetirementDone = nil
					continue
				}
				// Serve.
				reloading.Store(false)
				log.Warnln("[Reload] Serve")
				if pendingStagedHandoff != nil {
					if reflect.DeepEqual(pendingStagedHandoff.oldConf.Dns, conf.Dns) {
						c.SetPreparedDNSReuseHook(func() error {
							_ = c.ReuseDNSControllerFrom(pendingStagedHandoff.oldControlPlane)
							if c.ReuseDNSListenerFrom(pendingStagedHandoff.oldControlPlane) {
								return nil
							}
							return nil
						})
					}
					c.SetPreparedDNSStartHook(func() error {
						if c.ReuseDNSListenerFrom(pendingStagedHandoff.oldControlPlane) {
							return nil
						}
						if err := pendingStagedHandoff.oldControlPlane.StopDNSListener(); err != nil {
							log.WithError(err).Warnln("[Reload] Failed to stop previous DNS listener before staged cutover")
							return err
						}
						return nil
					})
				}
				readyChan := make(chan bool, 1)
				go func() {
					defer func() {
						select {
						case readyChan <- false:
						default:
						}
					}()
					if err := c.Serve(readyChan, listener); err != nil {
						log.Errorln("ListenAndServe:", err)
					}
					notifyRunStateChange(runStateChanges)
				}()
				waitResult, termSig := waitReloadReadyOrSignal(log, sigs, readyChan, reloadReadyTimeout)
				if waitResult == reloadReadyWaitSignal && termSig != nil {
					log.Infof("Received termination signal while waiting for reload readiness: %v", termSig.String())
					fastExit = true
					break loop
				}
				if waitResult != reloadReadyWaitReady {
					reloadingErr = fmt.Errorf("reload serve failed before becoming ready")
					if waitResult == reloadReadyWaitTimeout {
						reloadingErr = fmt.Errorf("reload serve timed out after %v", reloadReadyTimeout)
					}
					_ = sdnotify.Ready()
					_ = setRunSignalProgress(consts.ReloadError, reloadingErr.Error())
					log.WithError(reloadingErr).Errorln("[Reload] Reload serve failed before becoming ready")
					if pendingStagedHandoff != nil {
						rollbackStagedReloadHandoff(log, pendingStagedHandoff)
						if republishErr := pendingStagedHandoff.oldControlPlane.PublishListenerSockets(pendingStagedHandoff.oldListener); republishErr != nil {
							log.WithError(republishErr).Errorln("[Reload] Failed to republish previous listeners after staged handoff failure")
						}
						if rebuildErr := pendingStagedHandoff.oldControlPlane.RebuildReloadDatapath(); rebuildErr != nil {
							log.WithError(rebuildErr).Errorln("[Reload] Failed to rebuild previous datapath after staged handoff failure")
						}
						c = pendingStagedHandoff.oldControlPlane
						currCancel = pendingStagedHandoff.oldCancel
						conf = pendingStagedHandoff.oldConf
						listener = pendingStagedHandoff.oldListener
						if restartErr := c.RestartDNSListener(); restartErr != nil {
							log.WithError(restartErr).Warnln("[Reload] Failed to restart previous DNS listener after staged handoff rollback")
						}
						pendingStagedHandoff = nil
						log.Warnln("[Reload] Restored previous listener generation after staged handoff failure")
					}
					reloading.Store(false)
					reloadActive.Store(false)
					clearReloadPending(&reloadPending)
					continue
				}
				dnsHandoffActive := pendingStagedHandoff != nil &&
					pendingStagedHandoff.oldControlPlane != nil &&
					pendingStagedHandoff.oldControlPlane.SharesActiveDnsControllerWith(c)
				if pendingStagedHandoff != nil {
					oldListener := pendingStagedHandoff.oldListener
					oldC := pendingStagedHandoff.oldControlPlane
					oldCancel := pendingStagedHandoff.oldCancel
					abortConnections := pendingStagedHandoff.abortConnections
					if oldC != nil {
						bpf := oldC.EjectBpf()
						c.InjectBpf(bpf)
						c.InheritLpmIndices(oldC.EjectLpmIndices())
					}
					pendingStagedHandoff = nil

					if oldListener != nil {
						if err := oldListener.Close(); err != nil {
							log.WithError(err).Warnln("[Reload] Failed to close previous listener generation")
						}
					}

					if oldC != nil {
						lastRetirementMu.Lock()
						if lastRetirementCancel != nil {
							lastRetirementCancel()
						}
						retireCtx, retireCancel := context.WithCancel(context.Background())
						lastRetirementCancel = retireCancel
						lastRetirementMu.Unlock()

						log.Warnln("[Reload] Retiring old control plane")
						retirementDone := make(chan struct{})
						pendingRetirementDone = retirementDone
						drainBudget := remainingReloadRetirementBudget(pendingReloadRequestedAt, reloadTotalSwitchBudget)
						staleBeforeNs := pendingReloadRequestedAtMono
						successor := c
						go func(
							ctx context.Context,
							c *control.ControlPlane,
							successor *control.ControlPlane,
							cancel context.CancelFunc,
							abort bool,
							maxDrain time.Duration,
							staleBeforeNs uint64,
							done chan struct{},
						) {
							defer close(done)
							switch waitForControlPlaneDrain(log, ctx, c, maxDrain, controlPlaneRetirementLogEvery) {
							case controlPlaneDrainIdle:
								log.Infoln("[Reload] Old control plane drained active sessions; retiring immediately")
							case controlPlaneDrainCanceled:
								log.Warnln("[Reload] New generation ready; accelerating old generation retirement")
							case controlPlaneDrainTimeout:
								log.WithField("active_sessions", c.ActiveSessionCount()).
									Warnln("[Reload] Old control plane drain timed out; forcing retirement")
							}

							if abort {
								_ = c.AbortConnections()
							}
							if cancel != nil {
								cancel()
							}
							if closeErr := c.Close(); closeErr != nil {
								log.WithError(closeErr).Warnln("[Reload] Old control plane close did not finish cleanly")
							}
							if successor != nil {
								successor.RunReloadRetirementCleanup(staleBeforeNs)
							}
							log.Warnln("[Reload] Retired old control plane")
						}(retireCtx, oldC, successor, oldCancel, abortConnections, drainBudget, staleBeforeNs, retirementDone)
					}
				}
				_ = sdnotify.Ready()
				if reloadingErr == nil {
					_ = setRunSignalProgress(consts.ReloadDone, "OK")
				} else {
					_ = setRunSignalProgress(consts.ReloadError, reloadingErr.Error())
				}
				log.Warnln("[Reload] Finished")
				reloadActive.Store(false)
				if dnsHandoffActive && log.IsLevelEnabled(logrus.DebugLevel) {
					log.Debugln("[Reload] Shared DNS controller handoff remains available while old generation drains")
				}
				releaseReloadPendingAfterRetirement(&reloadPending, pendingRetirementDone)
				pendingRetirementDone = nil
			} else if listener == nil {
				// Listening error.
				log.Errorln("[Critical] Listener failed; exiting")
				break loop
			}
		}
	}

	defer func() {
		_ = sdnotify.Stopping()
		if pprofServer != nil {
			log.Infoln("Shutting down pprof server")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = pprofServer.Shutdown(ctx)
			cancel()
		}
		_ = os.Remove(PidFilePath)
	}()

	// Stop accepting new ingress immediately so shutdown does not continue to
	// create fresh UDP/TCP work while the control plane is being torn down.
	var shutdownHandoff *signalShutdownStagedHandoff
	if pendingStagedHandoff != nil {
		shutdownHandoff = &signalShutdownStagedHandoff{
			oldListener:     pendingStagedHandoff.oldListener,
			oldControlPlane: pendingStagedHandoff.oldControlPlane,
			newListener:     pendingStagedHandoff.newListener,
			newControlPlane: pendingStagedHandoff.newControlPlane,
		}
	}
	return shutdownAfterSignalWithHandoff(log, listener, c, control.GetDaeNetns(), fastExit, shutdownHandoff)
}

func notifyRunStateChange(runStateChanges chan<- struct{}) {
	select {
	case runStateChanges <- struct{}{}:
	default:
	}
}

func beginReloadHandoff(reloading *atomic.Bool, runStateChanges chan<- struct{}) {
	if reloading != nil {
		reloading.Store(true)
	}
	notifyRunStateChange(runStateChanges)
}

func waitForControlPlaneDrain(
	log *logrus.Logger,
	ctx context.Context,
	c reloadRetirementControlPlane,
	maxWait time.Duration,
	logEvery time.Duration,
) controlPlaneDrainWaitResult {
	if c == nil || c.ActiveSessionCount() == 0 {
		return controlPlaneDrainIdle
	}

	idleCh := c.DrainIdleCh()

	timer := time.NewTimer(maxWait)
	defer timer.Stop()

	var ticker *time.Ticker
	var tickCh <-chan time.Time
	if logEvery > 0 {
		ticker = time.NewTicker(logEvery)
		defer ticker.Stop()
		tickCh = ticker.C
	}

	for {
		select {
		case <-ctx.Done():
			return controlPlaneDrainCanceled
		case <-idleCh:
			return controlPlaneDrainIdle
		case <-timer.C:
			return controlPlaneDrainTimeout
		case <-tickCh:
			if log != nil && log.IsLevelEnabled(logrus.DebugLevel) {
				log.WithField("active_sessions", c.ActiveSessionCount()).
					Debugln("[Reload] Old control plane still draining active sessions")
			}
		}
	}
}

func rollbackStagedReloadHandoff(log *logrus.Logger, handoff *stagedReloadHandoff) {
	if handoff == nil {
		return
	}

	if handoff.newListener != nil {
		if err := handoff.newListener.Close(); err != nil && log != nil {
			log.WithError(err).Warnln("[Reload] Failed to close prepared listener during rollback")
		}
	}

	if handoff.newCancel != nil {
		handoff.newCancel()
	}
	if handoff.newControlPlane != nil {
		if err := handoff.newControlPlane.Close(); err != nil && log != nil {
			log.WithError(err).Warnln("[Reload] Failed to close staged control plane during rollback")
		}
	}
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
			case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL:
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

func shutdownAfterSignal(
	log *logrus.Logger,
	listener signalShutdownListener,
	c signalShutdownControlPlane,
	netns signalShutdownNetns,
	fastExit bool,
) error {
	return shutdownAfterSignalWithHandoff(log, listener, c, netns, fastExit, nil)
}

func shutdownAfterSignalWithHandoff(
	log *logrus.Logger,
	listener signalShutdownListener,
	c signalShutdownControlPlane,
	netns signalShutdownNetns,
	fastExit bool,
	handoff *signalShutdownStagedHandoff,
) error {
	closeListener := func(listener signalShutdownListener) {
		if listener == nil {
			return
		}
		if e := listener.Close(); e != nil {
			log.Warnf("close listener: %v", e)
		}
	}
	detachPlane := func(c signalShutdownControlPlane) {
		if c == nil {
			return
		}
		if e := c.DetachBpfHooks(); e != nil {
			log.Warnf("detach BPF hooks: %v", e)
		}
	}
	abortAndClosePlane := func(c signalShutdownControlPlane) error {
		if c == nil {
			return nil
		}
		if e := c.AbortConnections(); e != nil {
			log.Warnf("abort connections: %v", e)
		}
		if e := c.Close(); e != nil {
			return e
		}
		return nil
	}

	closeListener(listener)
	if handoff != nil {
		if handoff.oldListener != nil && handoff.oldListener != listener {
			closeListener(handoff.oldListener)
		}
		if handoff.newListener != nil && handoff.newListener != listener && handoff.newListener != handoff.oldListener {
			closeListener(handoff.newListener)
		}
	}

	detachPlane(c)
	if handoff != nil {
		if handoff.oldControlPlane != nil && handoff.oldControlPlane != c {
			detachPlane(handoff.oldControlPlane)
		}
		if handoff.newControlPlane != nil && handoff.newControlPlane != c && handoff.newControlPlane != handoff.oldControlPlane {
			detachPlane(handoff.newControlPlane)
		}
	}

	if fastExit {
		log.Infoln("[Shutdown] Fast exit enabled; skipping in-process netns and control-plane teardown. Residual kernel state will be purged on next startup.")
		return nil
	}

	if netns != nil {
		if e := netns.Close(); e != nil {
			log.Warnf("close dae netns: %v", e)
		}
	}

	var closeErrs []error
	if err := abortAndClosePlane(c); err != nil {
		closeErrs = append(closeErrs, err)
	}
	if handoff != nil {
		if handoff.oldControlPlane != nil && handoff.oldControlPlane != c {
			if err := abortAndClosePlane(handoff.oldControlPlane); err != nil {
				closeErrs = append(closeErrs, err)
			}
		}
		if handoff.newControlPlane != nil && handoff.newControlPlane != c && handoff.newControlPlane != handoff.oldControlPlane {
			if err := abortAndClosePlane(handoff.newControlPlane); err != nil {
				closeErrs = append(closeErrs, err)
			}
		}
	}
	if len(closeErrs) > 0 {
		return fmt.Errorf("close control plane: %w", errors.Join(closeErrs...))
	}
	return nil
}

func newControlPlane(ctx context.Context, log *logrus.Logger, bpf any, dnsCache map[string]*control.DnsCache, conf *config.Config, externGeoDataDirs []string) (c *control.ControlPlane, err error) {
	return newControlPlaneWithMode(ctx, log, bpf, dnsCache, conf, externGeoDataDirs, false)
}

func newPreparedControlPlane(ctx context.Context, log *logrus.Logger, bpf any, dnsCache map[string]*control.DnsCache, conf *config.Config, externGeoDataDirs []string) (c *control.ControlPlane, err error) {
	return newControlPlaneWithMode(ctx, log, bpf, dnsCache, conf, externGeoDataDirs, true)
}

func newControlPlaneWithMode(ctx context.Context, log *logrus.Logger, bpf any, dnsCache map[string]*control.DnsCache, conf *config.Config, externGeoDataDirs []string, prepareOnly bool) (c *control.ControlPlane, err error) {
	// Deep copy to prevent modification.
	conf = deepcopy.Copy(conf).(*config.Config)
	if conf.Global.SoMarkFromDae == 0 {
		var autoSelected bool
		conf.Global.SoMarkFromDae, autoSelected = common.ResolveSoMarkFromDae(conf.Global.SoMarkFromDae, conf.Global.SoMarkFromDaeSet)
		if autoSelected {
			log.Warnf("so_mark_from_dae is unset; using internal socket mark %#x to prevent dae UDP self-capture", conf.Global.SoMarkFromDae)
		}
	}

	/// Get tag -> nodeList mapping.
	tagToNodeList := map[string][]string{}
	// On initial startup (not reload), purge stale TC filters left by any previous process.
	if bpf == nil {
		control.PurgeStaleTCFilters(log)
	}
	if len(conf.Node) > 0 {
		for _, node := range conf.Node {
			tagToNodeList[""] = append(tagToNodeList[""], string(node))
		}
	}

	/// Init Direct Dialers.
	direct.InitDirectDialers(conf.Global.FallbackResolver)
	netutils.FallbackDns = netip.MustParseAddrPort(conf.Global.FallbackResolver)
	locationFinder := assets.NewLocationFinder(externGeoDataDirs)
	daeDNSRouter, err := daedns.NewWithOption(log, &conf.Global, &conf.Dns, &daedns.NewOption{LocationFinder: locationFinder})
	if err != nil {
		return nil, err
	}

	// Start timing the startup process
	startTime := time.Now()
	stageStart := startTime

	// Resolve subscriptions to nodes.
	resolvingfailed := false
	if !conf.Global.DisableWaitingNetwork {
		epo := 5 * time.Second
		client := http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (c net.Conn, err error) {
					conn, err := direct.SymmetricDirect.DialContext(ctx, common.MagicNetwork("tcp", conf.Global.SoMarkFromDae, conf.Global.Mptcp), addr)
					if err != nil {
						return nil, err
					}
					return &netproxy.FakeNetConn{
						Conn:  conn,
						LAddr: nil,
						RAddr: nil,
					}, nil
				},
			},
			Timeout: epo,
		}
		log.Infoln("Waiting for network...")
		for i := 0; ; i++ {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			resp, err := client.Get(CheckNetworkLinks[i%len(CheckNetworkLinks)])
			if err != nil {
				log.Debugln("CheckNetwork:", err)
				var neterr net.Error
				if errors.As(err, &neterr) && neterr.Timeout() {
					// Do not sleep.
					continue
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(epo):
				}
				continue
			}
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				break
			}
			log.Infof("Bad status: %v (%v)", resp.Status, resp.StatusCode)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(epo):
			}
		}
		log.Infoln("Network online.")
	}
	if len(conf.Subscription) > 0 {
		log.Infoln("Fetching subscriptions...")
	}
	// Parallelize subscription resolution to improve startup performance.
	// Use a semaphore to limit concurrency and avoid overwhelming the network.
	type subscriptionResult struct {
		tag   string
		nodes []string
		err   error
		sub   config.KeyableString
	}
	numSubscriptions := len(conf.Subscription)
	if numSubscriptions > 0 {
		// Limit concurrency to 4 subscriptions at a time to avoid overwhelming network
		maxConcurrency := 4
		if numSubscriptions < maxConcurrency {
			maxConcurrency = numSubscriptions
		}
		sem := make(chan struct{}, maxConcurrency)
		results := make(chan subscriptionResult, numSubscriptions)

		for _, sub := range conf.Subscription {
			go func(s config.KeyableString) {
				sem <- struct{}{}        // Acquire semaphore
				defer func() { <-sem }() // Release semaphore

				subDialer := direct.SymmetricDirect
				if daeDNSRouter != nil {
					wrappedDialer, wrapErr := daeDNSRouter.WrapSubscriptionDialer(subDialer, string(s))
					if wrapErr != nil {
						results <- subscriptionResult{
							err: wrapErr,
							sub: s,
						}
						return
					}
					subDialer = wrappedDialer
				}
				client := newHTTPClientForDialer(subDialer, 30*time.Second, conf.Global.SoMarkFromDae, conf.Global.Mptcp)
				tag, nodes, err := subscription.ResolveSubscription(log, &client, filepath.Dir(cfgFile), string(s))
				results <- subscriptionResult{
					tag:   tag,
					nodes: nodes,
					err:   err,
					sub:   s,
				}
			}(sub)
		}

		// Collect results
		for i := 0; i < numSubscriptions; i++ {
			result := <-results
			if result.err != nil {
				log.Warnf(`failed to resolve subscription "%v": %v`, result.sub, result.err)
				resolvingfailed = true
			}
			if len(result.nodes) > 0 {
				tagToNodeList[result.tag] = append(tagToNodeList[result.tag], result.nodes...)
			}
		}
		close(results)
		log.Infof("Subscriptions fetched in %v", time.Since(stageStart))
	}

	// Delete all files in persist.d that are not in tagToNodeList
	files, err := os.ReadDir(filepath.Join(filepath.Dir(cfgFile), "persist.d"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, file := range files {
		tag := strings.TrimSuffix(file.Name(), ".sub")
		if _, ok := tagToNodeList[tag]; !ok {
			err := os.Remove(filepath.Join(filepath.Dir(cfgFile), "persist.d", file.Name()))
			if err != nil {
				return nil, err
			}
		}
	}

	if len(tagToNodeList) == 0 {
		if resolvingfailed {
			log.Warnln("No node found because all subscription resolving failed.")
		} else {
			log.Warnln("No node found.")
		}
	}

	if len(conf.Global.LanInterface) == 0 && len(conf.Global.WanInterface) == 0 {
		log.Warnln("No interface to bind.")
	}

	if err = preprocessWanInterfaceAuto(conf); err != nil {
		return nil, err
	}

	// Start timing the control plane creation
	log.Infoln("Building control plane and routing rules...")
	stageStart = time.Now()
	if prepareOnly {
		c, err = control.NewPreparedControlPlaneWithContext(
			ctx,
			log,
			bpf,
			dnsCache,
			tagToNodeList,
			conf.Group,
			&conf.Routing,
			&conf.Global,
			&conf.Dns,
			externGeoDataDirs,
		)
	} else {
		c, err = control.NewControlPlaneWithContext(
			ctx,
			log,
			bpf,
			dnsCache,
			tagToNodeList,
			conf.Group,
			&conf.Routing,
			&conf.Global,
			&conf.Dns,
			externGeoDataDirs,
		)
	}
	if err != nil {
		return nil, err
	}
	log.Infof("Control plane built in %v", time.Since(stageStart))
	log.Infof("Total startup time: %v", time.Since(startTime))

	return c, nil
}

func newHTTPClientForDialer(d netproxy.Dialer, timeout time.Duration, soMark uint32, mptcp bool) http.Client {
	soMark = common.EffectiveSoMarkFromDae(soMark)
	return http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
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
		},
		Timeout: timeout,
	}
}

func preprocessWanInterfaceAuto(params *config.Config) error {
	// preprocess "auto".
	ifs := make([]string, 0, len(params.Global.WanInterface)+2)
	for _, ifname := range params.Global.WanInterface {
		if ifname == "auto" {
			defaultIfs, err := common.GetDefaultIfnames()
			if err != nil {
				return fmt.Errorf("failed to convert 'auto': %w", err)
			}
			ifs = append(ifs, defaultIfs...)
		} else {
			ifs = append(ifs, ifname)
		}
	}
	params.Global.WanInterface = common.Deduplicate(ifs)
	return nil
}

func readConfig(cfgFile string) (conf *config.Config, includes []string, err error) {
	merger := config.NewMerger(cfgFile)
	sections, includes, err := merger.Merge()
	if err != nil {
		return nil, nil, err
	}
	if conf, err = config.New(sections); err != nil {
		return nil, nil, err
	}
	return conf, includes, nil
}

func emptyConfig() (conf *config.Config, err error) {
	sections, err := config_parser.Parse(`global{} routing{}`)
	if err != nil {
		return nil, err
	}
	if conf, err = config.New(sections); err != nil {
		return nil, err
	}
	return conf, nil
}

func init() {
	rootCmd.AddCommand(runCmd)
}
