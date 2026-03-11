/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package lifecycle

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// LifecycleManager manages the lifecycle of dae with proper state machine,
// generation management, and systemd integration.
type LifecycleManager struct {
	log        *logrus.Logger
	mu         sync.RWMutex
	state      LifecycleState
	generation *Generation // Currently active generation
	pending    *Generation // Generation being prepared (during reload)
	notifier   *SystemdNotifier
	bridge     *ControlPlaneBridge // Control plane integration

	// Configuration
	drainTimeout  time.Duration
	cleanShutdown bool

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc
}

// ManagerConfig holds configuration for LifecycleManager.
type ManagerConfig struct {
	Log           *logrus.Logger
	DrainTimeout  time.Duration
	CleanShutdown bool
}

// NewLifecycleManager creates a new LifecycleManager in Created state.
func NewLifecycleManager(cfg *ManagerConfig) *LifecycleManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &LifecycleManager{
		log:           cfg.Log,
		state:         StateCreated,
		notifier:      NewSystemdNotifier(cfg.Log),
		bridge:        NewControlPlaneBridge(cfg.Log),
		drainTimeout:  cfg.DrainTimeout,
		cleanShutdown: cfg.CleanShutdown,
		ctx:           ctx,
		cancel:        cancel,
	}
}

// SetConfigFile sets the configuration file path.
func (m *LifecycleManager) SetConfigFile(cfgFile string, externGeoDataDirs []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bridge.SetConfig(cfgFile, externGeoDataDirs, m.drainTimeout, m.cleanShutdown)
}

// SetPidFile sets the pidfile configuration.
func (m *LifecycleManager) SetPidFile(pidFile string, disable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bridge.SetPidFile(pidFile, disable)
}

// GetControlPlane returns the current control plane.
func (m *LifecycleManager) GetControlPlane() *ControlPlaneBridge {
	return m.bridge
}

func (m *LifecycleManager) RuntimeErrors() <-chan error {
	return m.bridge.RuntimeErrors()
}

// AbortConnectionsNow forces active tracked connections to close without
// changing lifecycle state. Used to escalate a graceful stop.
func (m *LifecycleManager) AbortConnectionsNow(ctx context.Context) {
	gen := m.Generation()
	if gen == nil {
		return
	}
	m.abortConnections(ctx, gen)
}

// State returns the current state.
func (m *LifecycleManager) State() LifecycleState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// Generation returns the currently active generation.
func (m *LifecycleManager) Generation() *Generation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.generation
}

// transition attempts to transition to a new state.
// Returns error if the transition is not valid.
func (m *LifecycleManager) transition(to LifecycleState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.state.CanTransitionTo(to) {
		return fmt.Errorf("invalid state transition: %s -> %s", m.state, to)
	}

	m.log.Debugf("lifecycle state transition: %s -> %s", m.state, to)
	m.state = to
	return nil
}

// setState sets the state without validation (internal use).
func (m *LifecycleManager) setState(to LifecycleState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = to
}

// Start initiates the startup sequence: Created -> Starting -> Running.
// Returns the active generation on success.
func (m *LifecycleManager) Start(ctx context.Context, req *StartRequest) (*Generation, error) {
	const op = "start"

	// Validate initial state
	if m.State() != StateCreated {
		return nil, &LifecycleError{
			Op:    op,
			Phase: string(PhasePrecheck),
			Cause: fmt.Errorf("invalid state for start: %s", m.state),
		}
	}

	genID := uuid.New().String()
	startTime := time.Now()

	m.log.Infof("[%s] Starting generation %s", op, genID)
	defer func() {
		duration := time.Since(startTime)
		m.log.Infof("[%s] Generation %s completed in %v", op, genID, duration)
	}()

	// Phase 1: PreCheck
	if err := m.transition(StateStarting); err != nil {
		return nil, err
	}

	if err := m.precheck(ctx, genID, req); err != nil {
		m.setState(StateStopped)
		return nil, NewStartError(PhasePrecheck, genID, err)
	}

	// Extend timeout for long prepare phase
	m.notifier.ExtendTimeout(60 * time.Second)

	// Phase 2: Prepare
	gen, err := m.prepare(ctx, genID, req)
	if err != nil {
		m.releaseGeneration(gen)
		m.setState(StateStopped)
		return nil, NewStartError(PhasePrepare, genID, err)
	}

	// Phase 3: Attach
	if err := m.attach(ctx, gen); err != nil {
		m.releaseGeneration(gen)
		m.setState(StateStopped)
		return nil, NewStartError(PhaseAttach, genID, err)
	}

	// Phase 4: Activate
	if err := m.activate(ctx, gen); err != nil {
		m.releaseGeneration(gen)
		m.setState(StateStopped)
		return nil, NewStartError(PhaseActivate, genID, err)
	}

	// Mark generation as active
	gen.MarkActivated(time.Now())
	m.mu.Lock()
	m.generation = gen
	m.mu.Unlock()

	// Transition to Running
	if err := m.transition(StateRunning); err != nil {
		m.releaseGeneration(gen)
		m.setState(StateStopped)
		return nil, err
	}

	// Send READY=1
	m.notifier.Ready()

	m.log.Infof("[%s] Generation %s is now active", op, genID)
	return gen, nil
}

// Reload initiates the reload sequence: Running -> Reloading -> Running.
// Supports both config-only and full reload paths.
func (m *LifecycleManager) Reload(ctx context.Context, req *ReloadRequest) (*Generation, error) {
	const op = "reload"

	// Validate initial state
	if m.State() != StateRunning {
		return nil, &LifecycleError{
			Op:    op,
			Phase: string(PhaseValidating),
			Cause: fmt.Errorf("invalid state for reload: %s", m.state),
		}
	}

	oldGen := m.Generation()
	if oldGen == nil {
		return nil, &LifecycleError{
			Op:    op,
			Phase: string(PhaseValidating),
			Cause: fmt.Errorf("no active generation"),
		}
	}

	genID := uuid.New().String()
	startTime := time.Now()

	m.log.Infof("[%s] Starting reload for generation %s -> %s", op, oldGen.ID, genID)
	defer func() {
		duration := time.Since(startTime)
		m.log.Infof("[%s] Reload completed in %v (path: %s)", op, duration, req.ReloadType)
	}()

	// Notify systemd of reload start
	m.notifier.NotifyReloading()

	// Transition to Reloading
	if err := m.transition(StateReloading); err != nil {
		return nil, err
	}

	// Phase 1: Validating
	reloadType, err := m.validateReload(ctx, oldGen, req)
	if err != nil {
		m.setState(StateRunning)
		m.notifier.ReloadErrno(1) // Signal reload failure to systemd
		return nil, NewReloadError(PhaseValidating, genID, err, nil, false)
	}
	req.ReloadType = reloadType

	// Phase 2: Preparing
	newGen, err := m.prepareReload(ctx, genID, oldGen, req)
	if err != nil {
		m.setState(StateRunning)
		m.notifier.ReloadErrno(1)
		return nil, NewReloadError(PhasePrepare, genID, err, nil, false)
	}

	// Phase 3: Cutover
	var rollbackErr error
	if err := m.cutover(ctx, oldGen, newGen, req); err != nil {
		// Attempt rollback
		m.log.Warnf("[%s] Cutover failed, attempting rollback", op)
		rollbackErr = m.rollback(ctx, oldGen, newGen, req)

		m.setState(StateRunning)
		m.notifier.ReloadErrno(1)

		// Clean up failed generation
		m.releaseGeneration(newGen)

		return nil, NewReloadError(PhaseCutover, genID, err, rollbackErr, true)
	}

	// Phase 4: DrainOld (for full reload)
	if req.ReloadType == ReloadTypeFull {
		if err := m.drainOld(ctx, oldGen); err != nil {
			m.log.Warnf("[%s] Failed to drain old generation: %v", op, err)
		}
	}

	// Mark new generation as active
	newGen.MarkActivated(time.Now())
	m.mu.Lock()
	m.generation = newGen
	m.pending = nil
	m.mu.Unlock()

	// Transition back to Running
	if err := m.transition(StateRunning); err != nil {
		m.releaseGeneration(newGen)
		m.setState(StateStopped)
		return nil, err
	}

	// Send READY=1 to signal reload completion
	m.notifier.NotifyReady()
	m.notifier.Statusf("Reloaded: %s -> %s (%s)", oldGen.ID[:8], newGen.ID[:8], reloadType)

	m.log.Infof("[%s] Generation %s is now active (old: %s)", op, newGen.ID, oldGen.ID)
	return newGen, nil
}

// Stop initiates the shutdown sequence: Running -> Stopping -> Stopped.
func (m *LifecycleManager) Stop(ctx context.Context, mode StopMode) error {
	const op = "stop"

	currentState := m.State()
	if currentState != StateRunning && currentState != StateReloading {
		return &LifecycleError{
			Op:    op,
			Phase: string(PhaseStopAccepting),
			Cause: fmt.Errorf("invalid state for stop: %s", m.state),
		}
	}

	gen := m.Generation()
	if gen == nil {
		m.setState(StateStopped)
		return nil
	}

	m.log.Infof("[%s] Stopping generation %s (mode: %s)", op, gen.ID, mode)

	// Notify systemd
	m.notifier.Stopping()

	// Transition to Stopping
	if err := m.transition(StateStopping); err != nil {
		return err
	}

	startTime := time.Now()
	var leaked []string

	// Phase 1: StopAccepting
	if err := m.stopAccepting(ctx, gen); err != nil {
		return NewStopError(PhaseStopAccepting, gen.ID, err, leaked)
	}

	// Phase 2: Drain
	if mode == StopModeGraceful {
		if err := m.drain(ctx, gen); err != nil {
			m.log.Warnf("[%s] Drain phase had issues: %v", op, err)
		}
	} else {
		m.abortConnections(ctx, gen)
	}

	// Phase 3: Release
	if err := m.release(ctx, gen); err != nil {
		leaked = append(leaked, "some resources may not have been released")
	}

	// Phase 4: FinalCleanup
	if err := m.finalCleanup(ctx, gen); err != nil {
		m.log.Warnf("[%s] Final cleanup had issues: %v", op, err)
	}

	// Clear active generation
	m.mu.Lock()
	m.generation = nil
	m.mu.Unlock()

	// Transition to Stopped
	if err := m.transition(StateStopped); err != nil {
		return err
	}

	m.log.Infof("[%s] Generation %s stopped in %v", op, gen.ID, time.Since(startTime))

	if len(leaked) > 0 {
		return NewStopError(PhaseFinalCleanup, gen.ID, fmt.Errorf("resources leaked"), leaked)
	}
	return nil
}

// StartRequest holds parameters for the Start operation.
type StartRequest struct {
	ConfigFile        string
	LogFile           string
	ExternGeoDataDirs []string
	AutoSu            bool
	Config            *config.Config // Pre-parsed config (optional, avoids circular dependency)
	ConfigIncludes    []string       // Config include files
}

// ReloadRequest holds parameters for the Reload operation.
type ReloadRequest struct {
	Config     any // *config.Config
	ConfigHash string
	AbortConns bool
	ReloadType ReloadType // Detected during validation
	ForceReset bool
}

// StopMode determines how connections are handled during stop.
type StopMode int

const (
	StopModeGraceful  StopMode = iota // Wait for connections to finish
	StopModeImmediate                 // Abort connections immediately
)

// String returns the string representation of the stop mode.
func (m StopMode) String() string {
	switch m {
	case StopModeGraceful:
		return "graceful"
	case StopModeImmediate:
		return "immediate"
	default:
		return "unknown"
	}
}

// Phase implementations below
// These delegate to the ControlPlaneBridge for actual implementation.

func (m *LifecycleManager) precheck(ctx context.Context, genID string, req *StartRequest) error {
	m.log.Debugf("[%s] Precheck phase", genID)
	return m.bridge.Precheck(ctx, genID, req)
}

func (m *LifecycleManager) prepare(ctx context.Context, genID string, req *StartRequest) (*Generation, error) {
	m.log.Debugf("[%s] Prepare phase", genID)
	return m.bridge.Prepare(ctx, genID, req)
}

func (m *LifecycleManager) attach(ctx context.Context, gen *Generation) error {
	m.log.Debugf("[%s] Attach phase", gen.ID)
	return m.bridge.Attach(ctx, gen)
}

func (m *LifecycleManager) activate(ctx context.Context, gen *Generation) error {
	m.log.Debugf("[%s] Activate phase", gen.ID)
	return m.bridge.Activate(ctx, gen)
}

func (m *LifecycleManager) validateReload(ctx context.Context, oldGen *Generation, req *ReloadRequest) (ReloadType, error) {
	m.log.Debugf("[%s->?] Validate phase", oldGen.ID)
	return m.bridge.ValidateReload(ctx, oldGen, req)
}

func (m *LifecycleManager) prepareReload(ctx context.Context, genID string, oldGen *Generation, req *ReloadRequest) (*Generation, error) {
	m.log.Debugf("[%s] Prepare phase (reload type: %s)", genID, req.ReloadType)
	return m.bridge.PrepareReload(ctx, genID, oldGen, req)
}

func (m *LifecycleManager) cutover(ctx context.Context, oldGen, newGen *Generation, req *ReloadRequest) error {
	m.log.Debugf("[%s -> %s] Cutover phase", oldGen.ID, newGen.ID)
	return m.bridge.Cutover(ctx, oldGen, newGen, req)
}

func (m *LifecycleManager) rollback(ctx context.Context, oldGen, newGen *Generation, req *ReloadRequest) error {
	m.log.Debugf("[%s -> %s] Rollback phase", newGen.ID, oldGen.ID)
	return m.bridge.Rollback(ctx, oldGen, newGen, req)
}

func (m *LifecycleManager) drainOld(ctx context.Context, oldGen *Generation) error {
	m.log.Debugf("[%s] DrainOld phase", oldGen.ID)
	return m.bridge.DrainOld(ctx, oldGen)
}

func (m *LifecycleManager) stopAccepting(ctx context.Context, gen *Generation) error {
	m.log.Debugf("[%s] StopAccepting phase", gen.ID)
	return m.bridge.StopAccepting(ctx, gen)
}

func (m *LifecycleManager) drain(ctx context.Context, gen *Generation) error {
	m.log.Debugf("[%s] Drain phase (timeout: %v)", gen.ID, m.drainTimeout)
	return m.bridge.Drain(ctx, gen, m.drainTimeout)
}

func (m *LifecycleManager) abortConnections(ctx context.Context, gen *Generation) {
	m.log.Debugf("[%s] Abort connections", gen.ID)
	m.bridge.AbortConnections(ctx, gen)
}

func (m *LifecycleManager) release(ctx context.Context, gen *Generation) error {
	m.log.Debugf("[%s] Release phase", gen.ID)
	return m.bridge.Release(ctx, gen)
}

func (m *LifecycleManager) finalCleanup(ctx context.Context, gen *Generation) error {
	m.log.Debugf("[%s] FinalCleanup phase", gen.ID)
	return m.bridge.FinalCleanup(ctx, gen)
}

func (m *LifecycleManager) releaseGeneration(gen *Generation) {
	if gen == nil {
		return
	}
	if err := gen.Close(); err != nil {
		m.log.Warnf("Failed to release generation %s: %v", gen.ID, err)
	}
}

// Close shuts down the lifecycle manager.
func (m *LifecycleManager) Close() error {
	m.cancel()
	return m.bridge.Close()
}
