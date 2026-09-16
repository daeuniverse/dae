/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"errors"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
)

func TestFreshRollbackStopsAfterTCHookOwnershipRestoreFailure(t *testing.T) {
	wantErr := errors.New("ownership mismatch")
	original := restoreTCHookSetOwnershipFunc
	restoreTCHookSetOwnershipFunc = func(*control.ControlPlane, *control.ControlPlane) error {
		return wantErr
	}
	t.Cleanup(func() { restoreTCHookSetOwnershipFunc = original })

	handoff := &stagedReloadHandoff{
		oldControlPlane:   &control.ControlPlane{},
		oldConf:           &config.Config{},
		newControlPlane:   &control.ControlPlane{},
		tcHookSetAdopted:  true,
		hookFlipCommitted: true,
	}
	_, err := rollbackFreshDatapathReloadHandoff(nil, handoff)
	if !errors.Is(err, errTCHookOwnershipRestore) || !errors.Is(err, wantErr) {
		t.Fatalf("rollback error=%v, want ownership sentinel and cause", err)
	}
	if !handoff.hookFlipCommitted {
		t.Fatal("rollback continued into HookSet mutation after ownership restore failure")
	}
}

func TestSharedRollbackStopsAfterTCHookOwnershipRestoreFailure(t *testing.T) {
	wantErr := errors.New("ownership mismatch")
	original := restoreTCHookSetOwnershipFunc
	restoreTCHookSetOwnershipFunc = func(*control.ControlPlane, *control.ControlPlane) error {
		return wantErr
	}
	t.Cleanup(func() { restoreTCHookSetOwnershipFunc = original })

	handoff := &stagedReloadHandoff{
		oldControlPlane:   &control.ControlPlane{},
		newControlPlane:   &control.ControlPlane{},
		tcHookSetAdopted:  true,
		hookFlipCommitted: true,
	}
	err := rollbackStagedReloadHandoff(nil, handoff)
	if !errors.Is(err, errTCHookOwnershipRestore) || !errors.Is(err, wantErr) {
		t.Fatalf("rollback error=%v, want ownership sentinel and cause", err)
	}
	if !handoff.hookFlipCommitted {
		t.Fatal("rollback continued into HookSet mutation after ownership restore failure")
	}
}
