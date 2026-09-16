/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"reflect"
	"sync"

	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

// egressRuntime keeps only the concrete egress resources selected by live
// flows after their control plane retires. The control plane owns the initial
// reference; each established flow holds one additional dialer-specific lease.
type egressRuntime struct {
	log *logrus.Logger

	mu            sync.Mutex
	refs          int
	ownerReleased bool
	closed        bool
	cleanup       []func() error
	cleanupErr    error
	cleanupDone   chan struct{}

	resourceMode       bool
	groups             []*outbound.DialerGroup
	dialerRefs         map[*dialer.Dialer]int
	snapshots          map[egressBindingKey]*outbound.DialerGroup
	forgetDialerEpochs func([]*dialer.Dialer)
}

type egressBindingKey struct {
	group  *outbound.DialerGroup
	dialer *dialer.Dialer
}

type egressRuntimeActions struct {
	groups  []*outbound.DialerGroup
	retire  []*dialer.Dialer
	close   []*dialer.Dialer
	forget  []*dialer.Dialer
	cleanup []func() error
	final   bool
}

func newEgressRuntime(log *logrus.Logger, cleanup []func() error) *egressRuntime {
	return &egressRuntime{
		log:         log,
		refs:        1,
		cleanup:     append([]func() error(nil), cleanup...),
		cleanupDone: make(chan struct{}),
	}
}

// configureResources enables concrete dialer ownership. It must run before
// the runtime is exposed to connection admission.
func (r *egressRuntime) configureResources(
	groups []*outbound.DialerGroup,
	dialers []*dialer.Dialer,
	forgetDialerEpochs func([]*dialer.Dialer),
) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ownerReleased || r.closed || r.refs != 1 {
		panic("configure egress resources after flow admission")
	}
	r.resourceMode = true
	r.forgetDialerEpochs = forgetDialerEpochs
	r.dialerRefs = make(map[*dialer.Dialer]int, len(dialers))
	r.snapshots = make(map[egressBindingKey]*outbound.DialerGroup)
	seenGroups := make(map[*outbound.DialerGroup]struct{}, len(groups))
	for _, group := range groups {
		if group == nil {
			continue
		}
		if _, exists := seenGroups[group]; exists {
			continue
		}
		seenGroups[group] = struct{}{}
		r.groups = append(r.groups, group)
	}
	for _, d := range dialers {
		if d != nil {
			r.dialerRefs[d] = 0
		}
	}
}

type egressRuntimeLease struct {
	runtime *egressRuntime
	dialer  *dialer.Dialer
	once    sync.Once
}

func (r *egressRuntime) acquireEgress(selected *dialer.Dialer, group *outbound.DialerGroup) (*egressRuntimeLease, *outbound.DialerGroup, bool) {
	if r == nil {
		return nil, group, true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ownerReleased || r.closed {
		return nil, nil, false
	}

	retainedGroup := group
	if r.resourceMode {
		if selected == nil {
			return nil, nil, false
		}
		refs, exists := r.dialerRefs[selected]
		if !exists {
			return nil, nil, false
		}
		r.dialerRefs[selected] = refs + 1
		if group != nil {
			key := egressBindingKey{group: group, dialer: selected}
			retainedGroup = r.snapshots[key]
			if retainedGroup == nil {
				retainedGroup = group.SnapshotForEstablishedFlow(selected)
				r.snapshots[key] = retainedGroup
			}
		}
	}
	r.refs++
	return &egressRuntimeLease{runtime: r, dialer: selected}, retainedGroup, true
}

func (r *egressRuntime) releaseOwner() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.ownerReleased {
		done := r.cleanupDone
		closed := r.closed
		r.mu.Unlock()
		if closed {
			<-done
			r.mu.Lock()
			err := r.cleanupErr
			r.mu.Unlock()
			return err
		}
		return nil
	}
	r.ownerReleased = true
	actions := r.releaseOwnerLocked()
	r.mu.Unlock()
	return r.runActions(actions)
}

func (l *egressRuntimeLease) release() error {
	if l == nil {
		return nil
	}
	var err error
	l.once.Do(func() {
		r := l.runtime
		if r == nil {
			return
		}
		r.mu.Lock()
		actions := r.releaseLeaseLocked(l.dialer)
		r.mu.Unlock()
		err = r.runActions(actions)
	})
	return err
}

func (r *egressRuntime) releaseOwnerLocked() egressRuntimeActions {
	actions := egressRuntimeActions{}
	if r.refs == 0 {
		return actions
	}
	r.refs--
	if r.resourceMode {
		actions.groups = r.groups
		r.groups = nil
		// Snapshot keys point at the full groups. Live flows retain only values,
		// each of which contains the selected dialer alone.
		r.snapshots = nil
		activeTransports := make(map[any]struct{})
		for d, refs := range r.dialerRefs {
			if refs > 0 {
				activeTransports[egressDialerIdentity(d)] = struct{}{}
			}
		}
		closedTransports := make(map[any]struct{})
		for d, refs := range r.dialerRefs {
			identity := egressDialerIdentity(d)
			if _, active := activeTransports[identity]; active {
				actions.retire = append(actions.retire, d)
				if refs == 0 {
					actions.forget = append(actions.forget, d)
					delete(r.dialerRefs, d)
				}
				continue
			}
			if _, alreadyClosed := closedTransports[identity]; alreadyClosed {
				actions.retire = append(actions.retire, d)
			} else {
				actions.close = append(actions.close, d)
				closedTransports[identity] = struct{}{}
			}
			actions.forget = append(actions.forget, d)
			delete(r.dialerRefs, d)
		}
	}
	r.finishLocked(&actions)
	return actions
}

func (r *egressRuntime) releaseLeaseLocked(selected *dialer.Dialer) egressRuntimeActions {
	actions := egressRuntimeActions{}
	if r.refs == 0 {
		return actions
	}
	r.refs--
	if r.resourceMode && selected != nil {
		if refs, exists := r.dialerRefs[selected]; exists {
			refs--
			if refs <= 0 {
				if r.ownerReleased {
					delete(r.dialerRefs, selected)
					actions.forget = append(actions.forget, selected)
					identity := egressDialerIdentity(selected)
					transportActive := false
					for d, otherRefs := range r.dialerRefs {
						if otherRefs > 0 && egressDialerIdentity(d) == identity {
							transportActive = true
							break
						}
					}
					if transportActive {
						actions.retire = append(actions.retire, selected)
					} else {
						actions.close = append(actions.close, selected)
					}
				} else {
					r.dialerRefs[selected] = 0
				}
			} else {
				r.dialerRefs[selected] = refs
			}
		}
	}
	r.finishLocked(&actions)
	return actions
}

func egressDialerIdentity(d *dialer.Dialer) any {
	if d == nil || d.Dialer == nil {
		return d
	}
	identity := any(d.Dialer)
	if typ := reflect.TypeOf(identity); typ != nil && typ.Comparable() &&
		(typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Chan || typ.Kind() == reflect.UnsafePointer) {
		return identity
	}
	// Conservatively isolate unusual value-based implementations whose dynamic
	// value cannot be used as a map key.
	return d
}

func (r *egressRuntime) finishLocked(actions *egressRuntimeActions) {
	if r.refs != 0 || r.closed {
		return
	}
	r.closed = true
	actions.cleanup = r.cleanup
	r.cleanup = nil
	actions.final = true
}

func (r *egressRuntime) runActions(actions egressRuntimeActions) error {
	if r == nil {
		return nil
	}
	var errs []error
	for _, group := range actions.groups {
		if group != nil {
			if err := group.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for _, d := range actions.retire {
		d.RetireForEstablishedFlows()
	}
	if r.forgetDialerEpochs != nil {
		r.forgetDialerEpochs(actions.forget)
	}
	for _, d := range actions.close {
		if d != nil {
			if err := d.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for i := len(actions.cleanup) - 1; i >= 0; i-- {
		if actions.cleanup[i] == nil {
			continue
		}
		if err := actions.cleanup[i](); err != nil {
			errs = append(errs, err)
		}
	}
	err := stderrors.Join(errs...)

	r.mu.Lock()
	if err != nil {
		r.cleanupErr = stderrors.Join(r.cleanupErr, err)
	}
	if actions.final {
		close(r.cleanupDone)
		err = r.cleanupErr
	}
	r.mu.Unlock()
	if err != nil && r.log != nil {
		r.log.WithError(err).Warn("Failed to release retired egress runtime")
	}
	return err
}
