/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"testing"
)

func TestActiveControlPlanePublicationHandoff(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)

	oldPlane := &ControlPlane{}
	newPlane := &ControlPlane{}

	oldPlane.publishActiveControlPlane()
	assertActiveControlPlane(t, oldPlane)

	newPlane.publishActiveControlPlane()
	assertActiveControlPlane(t, newPlane)
}

// A retiring generation unpublishes after its successor has already taken over.
// That late unpublish must not clear the successor, or process-wide lookups
// would report no active control plane while one is serving traffic.
func TestActiveControlPlaneStaleUnpublishKeepsSuccessor(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)

	oldPlane := &ControlPlane{}
	newPlane := &ControlPlane{}
	oldPlane.publishActiveControlPlane()
	newPlane.publishActiveControlPlane()

	oldPlane.unpublishActiveControlPlane()
	assertActiveControlPlane(t, newPlane)

	newPlane.unpublishActiveControlPlane()
	assertActiveControlPlane(t, nil)
}

func assertActiveControlPlane(t *testing.T, want *ControlPlane) {
	t.Helper()
	activeControlPlanePublication.mu.RLock()
	got := activeControlPlanePublication.plane.Load()
	activeControlPlanePublication.mu.RUnlock()
	if got != want {
		t.Fatalf("active control plane = %p, want %p", got, want)
	}
}

func resetActiveControlPlanePublicationForTest(t *testing.T) {
	t.Helper()
	activeControlPlanePublication.mu.Lock()
	previous := activeControlPlanePublication.plane.Swap(nil)
	previousOwners := activeControlPlanePublication.owners
	activeControlPlanePublication.owners = nil
	activeControlPlanePublication.mu.Unlock()
	t.Cleanup(func() {
		activeControlPlanePublication.mu.Lock()
		activeControlPlanePublication.plane.Store(previous)
		activeControlPlanePublication.owners = previousOwners
		activeControlPlanePublication.mu.Unlock()
	})
}

func TestActiveDNSControllerReleasesGateOnPanic(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)

	controller := &DnsController{dnsControllerStore: newDnsControllerStore()}
	plane := &ControlPlane{
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{dnsController: controller},
	}
	plane.publishActiveControlPlane()

	func() {
		defer func() {
			if recovered := recover(); recovered == nil {
				t.Fatal("handler panic was not propagated")
			}
		}()
		_ = withActiveDNSController(nil, context.Background(), func(context.Context, *DnsController) error {
			panic("test handler panic")
		})
	}()

	if got := controller.handleInflight.Load(); got != 0 {
		t.Fatalf("handle inflight count = %d, want 0 after panic", got)
	}
}
