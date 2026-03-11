/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org
 */

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/lifecycle"
	"github.com/daeuniverse/dae/pkg/logger"
	"github.com/mohae/deepcopy"
	"github.com/okzk/sdnotify"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

// RunV2 is the new implementation using LifecycleManager.
// This function replaces the original Run() with proper lifecycle management.
func RunV2(log *logrus.Logger, cfgFile string, externGeoDataDirs []string) (err error) {
	// Remove AbortFile at beginning
	_ = os.Remove(AbortFile)

	// Read config first (in cmd package to avoid circular dependency)
	conf, includes, err := readConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	// Set up logging
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
	logger.SetLogger(log, conf.Global.LogLevel, disableTimestamp, logOpts)
	logger.SetLogger(logrus.StandardLogger(), conf.Global.LogLevel, disableTimestamp, logOpts)

	log.Infof("Include config files: [%v]", includes)

	// Create LifecycleManager
	mgr := lifecycle.NewLifecycleManager(&lifecycle.ManagerConfig{
		Log:           log,
		DrainTimeout:  30 * time.Second,
		CleanShutdown: false,
	})

	// Configure manager
	mgr.SetConfigFile(cfgFile, externGeoDataDirs)
	mgr.SetPidFile(PidFilePath, disablePidFile)

	// Create context for main loop
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the service with pre-parsed config
	gen, err := mgr.Start(ctx, &lifecycle.StartRequest{
		ConfigFile:        cfgFile,
		ExternGeoDataDirs: externGeoDataDirs,
		Config:            conf,
		ConfigIncludes:    includes,
	})
	if err != nil {
		return fmt.Errorf("start failed: %w", err)
	}

	log.Infof("Started generation %s", gen.ID)

	// Signal systemd that we're ready (only if Activate succeeded)
	// The Activate phase already verified the listener started successfully
	sdnotify.Ready()

	// Update signal progress file to indicate ready
	_ = os.WriteFile(SignalProgressFilePath, []byte{consts.ReloadDone}, 0644)

	// Setup signal handling
	return runSignalLoopV2(ctx, log, mgr, cfgFile, externGeoDataDirs, conf)
}

// runSignalLoopV2 handles signals for the running service.
func runSignalLoopV2(
	ctx context.Context,
	log *logrus.Logger,
	mgr *lifecycle.LifecycleManager,
	cfgFile string,
	externGeoDataDirs []string,
	initialConf *config.Config,
) error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)
	defer signal.Stop(sigs)

	currentConf := initialConf
	var (
		stopResultCh chan error
		stopMode     lifecycle.StopMode
	)

	startStop := func(mode lifecycle.StopMode) {
		if stopResultCh != nil {
			return
		}
		stopMode = mode
		stopResultCh = make(chan error, 1)
		go func() {
			stopResultCh <- handleStopV2(ctx, log, mgr, mode)
		}()
	}

	escalateStop := func() {
		if stopResultCh == nil || stopMode == lifecycle.StopModeImmediate {
			return
		}
		stopMode = lifecycle.StopModeImmediate
		log.Warn("[Signal] Received additional stop signal - aborting active connections")
		mgr.AbortConnectionsNow(context.Background())
	}

	for {
		select {
		case sig := <-sigs:
			switch sig {
			case syscall.SIGUSR2:
				// Suspend (empty profile)
				log.Warn("[Signal] Received suspend signal")
				newConf, err := handleReloadV2(ctx, log, mgr, cfgFile, externGeoDataDirs, currentConf, true)
				if err != nil {
					log.Errorf("Suspend failed: %v", err)
				} else if newConf != nil {
					currentConf = newConf
				}

			case syscall.SIGUSR1, syscall.SIGHUP:
				// Reload
				log.Warn("[Signal] Received reload signal")
				newConf, err := handleReloadV2(ctx, log, mgr, cfgFile, externGeoDataDirs, currentConf, false)
				if err != nil {
					log.Errorf("Reload failed: %v", err)
				} else if newConf != nil {
					currentConf = newConf
				}

			case syscall.SIGINT, syscall.SIGTERM:
				if stopResultCh == nil {
					log.Warn("[Signal] Received stop signal - graceful shutdown")
					startStop(lifecycle.StopModeGraceful)
				} else {
					escalateStop()
				}

			case syscall.SIGQUIT:
				if stopResultCh == nil {
					log.Warn("[Signal] Received quit signal - immediate shutdown")
					startStop(lifecycle.StopModeImmediate)
				} else {
					escalateStop()
				}

			default:
				log.Infof("[Signal] Received signal: %v", sig)
			}

		case <-ctx.Done():
			if stopResultCh == nil {
				log.Info("[Signal] Context cancelled - shutting down")
				startStop(lifecycle.StopModeGraceful)
			}
		case err := <-mgr.RuntimeErrors():
			if err == nil {
				continue
			}
			log.Errorf("[Runtime] Active listener failed: %v", err)
			stopErr := handleStopV2(ctx, log, mgr, lifecycle.StopModeImmediate)
			if stopErr != nil {
				return errors.Join(err, stopErr)
			}
			return err
		case err := <-stopResultCh:
			return err
		}
	}
}

// handleReloadV2 processes a reload request.
func handleReloadV2(
	ctx context.Context,
	log *logrus.Logger,
	mgr *lifecycle.LifecycleManager,
	cfgFile string,
	externGeoDataDirs []string,
	oldConf *config.Config,
	isSuspend bool,
) (*config.Config, error) {
	// Send reloading notification
	sdnotify.Reloading()
	_ = os.WriteFile(SignalProgressFilePath, []byte{consts.ReloadProcessing}, 0644)

	// Check if we should abort connections
	abortConnections := os.Remove(AbortFile) == nil
	if abortConnections {
		log.Info("[Reload] Abort connections requested")
	}

	// Load new config
	var newConf *config.Config
	var err error
	var includes []string

	if isSuspend {
		// Suspend mode: use empty config
		newConf, err = emptyConfig()
		if err != nil {
			sdnotify.Ready()
			_ = os.WriteFile(SignalProgressFilePath,
				append([]byte{consts.ReloadError}, []byte("\n"+err.Error())...), 0644)
			return nil, fmt.Errorf("create empty config: %w", err)
		}
		// Copy global settings
		newConf.Global = deepcopy.Copy(oldConf.Global).(config.Global)
		newConf.Global.WanInterface = nil
		newConf.Global.LanInterface = nil
		newConf.Global.LogLevel = "warning"
		log.Info("[Reload] Suspending with empty profile")
	} else {
		// Normal reload: read config file
		newConf, includes, err = readConfig(cfgFile)
		if err != nil {
			sdnotify.Ready()
			_ = os.WriteFile(SignalProgressFilePath,
				append([]byte{consts.ReloadError}, []byte("\n"+err.Error())...), 0644)
			return nil, fmt.Errorf("read config: %w", err)
		}
		log.Infof("Include config files: [%v]", includes)
	}

	// Update logger
	logger.SetLogger(log, newConf.Global.LogLevel, disableTimestamp, nil)
	logger.SetLogger(logrus.StandardLogger(), newConf.Global.LogLevel, disableTimestamp, nil)

	// Perform reload
	reloadReq := &lifecycle.ReloadRequest{
		Config:     newConf,
		ConfigHash: lifecycle.ComputeConfigHash(newConf),
		AbortConns: abortConnections,
	}

	newGen, err := mgr.Reload(ctx, reloadReq)
	if err != nil {
		// Signal reload failure
		_ = os.WriteFile(SignalProgressFilePath,
			append([]byte{consts.ReloadError}, []byte("\n"+err.Error())...), 0644)
		sdnotify.Ready()
		return nil, fmt.Errorf("reload failed: %w", err)
	}

	// Signal reload success
	_ = os.WriteFile(SignalProgressFilePath,
		append([]byte{consts.ReloadDone}, []byte("\nOK")...), 0644)
	sdnotify.Ready()

	log.Infof("[Reload] Reloaded to generation %s", newGen.ID)
	return newConf, nil
}

// handleStopV2 processes a stop request.
func handleStopV2(
	ctx context.Context,
	log *logrus.Logger,
	mgr *lifecycle.LifecycleManager,
	mode lifecycle.StopMode,
) error {
	sdnotify.Stopping()

	err := mgr.Stop(ctx, mode)
	if err != nil {
		log.Errorf("Stop failed: %v", err)
		return err
	}

	log.Info("Stopped successfully")
	return nil
}
