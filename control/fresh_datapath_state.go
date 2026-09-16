/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"fmt"
	"maps"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
)

// FreshDatapathState is an opaque snapshot of process flow-state maps that a
// fresh program load must reuse to preserve established connections.
type FreshDatapathState struct {
	connState     *ebpf.Map
	redirectTrack *ebpf.Map
	cookiePID     *ebpf.Map
	connStateMax  uint32
}

// SnapshotFreshDatapathState captures the maps whose contents describe live
// connections rather than the policy used to admit new flows.
func (c *ControlPlane) SnapshotFreshDatapathState() (*FreshDatapathState, error) {
	if c == nil {
		return nil, fmt.Errorf("snapshot fresh datapath state: control plane is nil")
	}
	bpf := c.PeekBpf()
	if bpf == nil || bpf.ConnStateMap == nil || bpf.RedirectTrack == nil || bpf.CookiePidMap == nil {
		// Keep the construction boundary injectable for process-level lifecycle
		// tests. A real BPF load validates the opaque marker in apply below.
		return &FreshDatapathState{}, nil
	}
	return &FreshDatapathState{
		connState:     bpf.ConnStateMap,
		redirectTrack: bpf.RedirectTrack,
		cookiePID:     bpf.CookiePidMap,
		connStateMax:  bpf.ConnStateMap.MaxEntries(),
	}, nil
}

func (s *FreshDatapathState) apply(options *ebpf.CollectionOptions, requestedConnStateMax uint32, log *logrus.Logger) (uint32, error) {
	if s == nil {
		return requestedConnStateMax, nil
	}
	if options == nil || s.connState == nil || s.redirectTrack == nil || s.cookiePID == nil || s.connStateMax == 0 {
		return 0, fmt.Errorf("apply fresh datapath state: invalid flow-state snapshot")
	}
	replacements := make(map[string]*ebpf.Map, len(options.MapReplacements)+3)
	maps.Copy(replacements, options.MapReplacements)
	replacements["conn_state_map"] = s.connState
	replacements["redirect_track"] = s.redirectTrack
	replacements["cookie_pid_map"] = s.cookiePID
	options.MapReplacements = replacements
	if requestedConnStateMax != 0 && requestedConnStateMax != s.connStateMax && log != nil {
		log.WithFields(logrus.Fields{
			"active_max_entries":    s.connStateMax,
			"requested_max_entries": requestedConnStateMax,
		}).Warnln("[Reload] Deferring conn-state map size change until cold start to preserve established flows")
	}
	return s.connStateMax, nil
}

// AdoptProcessFlowDatapath switches process-owned conn-state cleanup to the
// successor's cloned map handles after a fresh program load.
func (c *ControlPlane) AdoptProcessFlowDatapath(previous *ControlPlane) error {
	if c == nil || previous == nil {
		return fmt.Errorf("adopt process flow datapath: both control planes are required")
	}
	manager, _ := c.controlPlaneSessionManager()
	previousManager, _ := previous.controlPlaneSessionManager()
	if manager == nil || manager != previousManager {
		return fmt.Errorf("adopt process flow datapath: control planes do not share a session manager")
	}
	previousBpf, successorBpf := previous.PeekBpf(), c.PeekBpf()
	if err := manager.adoptUDPDatapath(previousBpf, successorBpf); err != nil {
		return err
	}
	if err := c.adoptBpfMaintenanceCleanup(previous); err != nil {
		rollbackErr := manager.adoptUDPDatapath(successorBpf, previousBpf)
		return stderrors.Join(err, rollbackErr)
	}
	return nil
}

func (m *SessionManager) adoptUDPDatapath(previous, successor *bpfObjects) error {
	if m == nil || previous == nil || successor == nil || successor.ConnStateMap == nil {
		return fmt.Errorf("adopt UDP datapath: required BPF objects are unavailable")
	}
	m.udpStateMu.Lock()
	defer m.udpStateMu.Unlock()
	current := m.udpBPF.Load()
	if current != nil && current != previous {
		return fmt.Errorf("adopt UDP datapath: current owner does not match previous generation")
	}
	m.udpBPF.Store(successor)
	return nil
}
