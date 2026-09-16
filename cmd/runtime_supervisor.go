/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	stderrors "errors"
	"sync"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
)

var (
	errRuntimeSupervisorClosed            = stderrors.New("runtime supervisor is shut down")
	errRuntimeSupervisorNilGeneration     = stderrors.New("runtime generation is nil")
	errRuntimeSupervisorPrepared          = stderrors.New("runtime supervisor already has a prepared generation")
	errRuntimeSupervisorRetiring          = stderrors.New("runtime supervisor is waiting for a retiring generation")
	errRuntimeSupervisorNoPrepared        = stderrors.New("runtime supervisor has no prepared generation")
	errRuntimeSupervisorPreparedMismatch  = stderrors.New("runtime generation is not the prepared candidate")
	errRuntimeSupervisorGenerationManaged = stderrors.New("runtime generation is already managed")
)

// runtimeGeneration is one immutable runtime configuration and its resources.
// The supervisor transfers ownership of these resources as a unit.
type runtimeGeneration struct {
	controlPlane *control.ControlPlane
	listener     *control.Listener
	cancel       context.CancelFunc
	conf         *config.Config

	cleanupOnce sync.Once
	cleanupErr  error
}

// cleanup releases a generation's owned resources exactly once. Rollback
// paths may be reached from readiness failure, publish failure, or shutdown;
// making cleanup idempotent keeps those paths from racing into double close.
func (g *runtimeGeneration) cleanup() error {
	if g == nil {
		return nil
	}

	g.cleanupOnce.Do(func() {
		var errs []error
		if g.listener != nil {
			if err := g.listener.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if g.cancel != nil {
			g.cancel()
		}
		if g.controlPlane != nil {
			if err := g.controlPlane.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		g.cleanupErr = stderrors.Join(errs...)
	})
	return g.cleanupErr
}

// runtimeSupervisorSnapshot describes resources whose ownership was observed
// atomically. Callers that receive a shutdown snapshot own subsequent cleanup.
type runtimeSupervisorSnapshot struct {
	active   *runtimeGeneration
	prepared *runtimeGeneration
	retiring *runtimeGeneration
}

// runtimeSupervisor owns at most one active generation, one prepared
// candidate, and one retiring generation. A retiring generation blocks another
// prepare so the two routing epoch slots cannot be reused prematurely.
type runtimeSupervisor struct {
	mu sync.Mutex

	active   *runtimeGeneration
	prepared *runtimeGeneration
	retiring *runtimeGeneration
	closed   bool
}

func newRuntimeSupervisor(active *runtimeGeneration) *runtimeSupervisor {
	return &runtimeSupervisor{active: active}
}

// replaceActive aligns the supervisor with a legacy active generation before a
// staged handoff starts. It is only valid while no candidate is prepared and
// no previously published generation is still retiring.
func (s *runtimeSupervisor) replaceActive(active *runtimeGeneration) error {
	if active == nil {
		return errRuntimeSupervisorNilGeneration
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errRuntimeSupervisorClosed
	}
	if s.prepared != nil {
		return errRuntimeSupervisorPrepared
	}
	if s.retiring != nil {
		return errRuntimeSupervisorRetiring
	}

	s.active = active
	if active.controlPlane != nil {
		active.controlPlane.PublishActiveDebugState()
	}
	return nil
}

// installPrepared records a fully constructed candidate without changing the
// generation used by new flows. The caller retains cleanup ownership until it
// publishes the candidate or rolls it back.
func (s *runtimeSupervisor) installPrepared(candidate *runtimeGeneration) error {
	if candidate == nil {
		return errRuntimeSupervisorNilGeneration
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errRuntimeSupervisorClosed
	}
	if s.prepared != nil {
		return errRuntimeSupervisorPrepared
	}
	if s.retiring != nil {
		return errRuntimeSupervisorRetiring
	}
	if candidate == s.active {
		return errRuntimeSupervisorGenerationManaged
	}

	s.prepared = candidate
	return nil
}

// publishPrepared makes candidate active after the caller has completed its
// warmup and validation. It returns the previously active generation so the
// caller can drain it before marking retirement complete.
func (s *runtimeSupervisor) publishPrepared(candidate *runtimeGeneration) (*runtimeGeneration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, errRuntimeSupervisorClosed
	}
	if s.prepared == nil {
		return nil, errRuntimeSupervisorNoPrepared
	}
	if s.prepared != candidate {
		return nil, errRuntimeSupervisorPreparedMismatch
	}
	if s.retiring != nil {
		return nil, errRuntimeSupervisorRetiring
	}

	retiring := s.active
	s.active = candidate
	s.prepared = nil
	s.retiring = retiring
	if candidate.controlPlane != nil {
		candidate.controlPlane.PublishActiveDebugState()
	}
	return retiring, nil
}

// rollbackPrepared removes candidate without changing the active generation.
// It is a no-op when another caller has already changed the candidate state.
func (s *runtimeSupervisor) rollbackPrepared(candidate *runtimeGeneration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.prepared != candidate || candidate == nil {
		return
	}

	s.prepared = nil
}

// markRetirementComplete releases retiring only when completion belongs to the
// generation that is still retiring. Late completion notifications are ignored.
func (s *runtimeSupervisor) markRetirementComplete(retiring *runtimeGeneration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.retiring != retiring || retiring == nil {
		return
	}

	s.retiring = nil
}

// ownsRetiring reports whether generation is still owned by this supervisor's
// retirement task. A shutdown snapshot transfers ownership and returns false.
func (s *runtimeSupervisor) ownsRetiring(retiring *runtimeGeneration) bool {
	if s == nil || retiring == nil {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return !s.closed && s.retiring == retiring
}

// shutdown atomically transfers all generation cleanup ownership to the
// caller and rejects future state transitions.
func (s *runtimeSupervisor) shutdown() runtimeSupervisorSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	snapshot := runtimeSupervisorSnapshot{
		active:   s.active,
		prepared: s.prepared,
		retiring: s.retiring,
	}
	s.active = nil
	s.prepared = nil
	s.retiring = nil
	s.closed = true
	return snapshot
}
