/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	stderrors "errors"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/control"
)

func TestListenControlPlaneInDaeNetnsScopesListenerCreation(t *testing.T) {
	previousListen := listenControlPlaneFunc
	previousWithDaeNetns := withDaeNetnsRequiredFunc
	t.Cleanup(func() {
		listenControlPlaneFunc = previousListen
		withDaeNetnsRequiredFunc = previousWithDaeNetns
	})

	depth := 0
	withDaeNetnsRequiredFunc = func(op string, f func() error) error {
		if op != "listen control plane" {
			t.Fatalf("netns operation = %q, want listen control plane", op)
		}
		depth++
		defer func() { depth-- }()
		return f()
	}
	want := &control.Listener{}
	listenControlPlaneFunc = func(*control.ControlPlane, uint16) (*control.Listener, error) {
		if depth != 1 {
			t.Fatalf("listener created at netns depth %d, want 1", depth)
		}
		return want, nil
	}

	got, err := listenControlPlaneInDaeNetns(&control.ControlPlane{}, 12345)
	if err != nil {
		t.Fatalf("listenControlPlaneInDaeNetns() error = %v", err)
	}
	if got != want {
		t.Fatalf("listenControlPlaneInDaeNetns() listener = %p, want %p", got, want)
	}
}

func TestListenControlPlaneInDaeNetnsRejectsScopeAndListenerFailures(t *testing.T) {
	previousListen := listenControlPlaneFunc
	previousWithDaeNetns := withDaeNetnsRequiredFunc
	t.Cleanup(func() {
		listenControlPlaneFunc = previousListen
		withDaeNetnsRequiredFunc = previousWithDaeNetns
	})

	wantErr := stderrors.New("setns failed")
	withDaeNetnsRequiredFunc = func(string, func() error) error { return wantErr }
	if _, err := listenControlPlaneInDaeNetns(&control.ControlPlane{}, 12345); !stderrors.Is(err, wantErr) {
		t.Fatalf("scope failure error = %v, want %v", err, wantErr)
	}

	listenControlPlaneFunc = func(*control.ControlPlane, uint16) (*control.Listener, error) {
		return &control.Listener{}, nil
	}
	withDaeNetnsRequiredFunc = func(_ string, f func() error) error {
		if err := f(); err != nil {
			return err
		}
		return wantErr
	}
	if _, err := listenControlPlaneInDaeNetns(&control.ControlPlane{}, 12345); !stderrors.Is(err, wantErr) {
		t.Fatalf("restore failure error = %v, want %v", err, wantErr)
	}

	withDaeNetnsRequiredFunc = func(_ string, f func() error) error { return f() }
	listenControlPlaneFunc = func(*control.ControlPlane, uint16) (*control.Listener, error) { return nil, nil }
	if _, err := listenControlPlaneInDaeNetns(&control.ControlPlane{}, 12345); err == nil || !strings.Contains(err.Error(), "listener is nil") {
		t.Fatalf("nil listener error = %v, want descriptive failure", err)
	}
}
