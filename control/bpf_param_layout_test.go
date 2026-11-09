//go:build !dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"unsafe"
)

// TestDaeParamLayout pins daeParam field offsets to `struct dae_param` in
// kern/tproxy.c. cilium/ebpf writes the struct into .rodata by offset, so a
// silent layout drift would move a parameter rather than fail the load.
func TestDaeParamLayout(t *testing.T) {
	var p daeParam
	const wantSize = 32
	if got := unsafe.Sizeof(p); got != wantSize {
		t.Fatalf("daeParam size = %d, want %d (see struct dae_param in kern/tproxy.c)", got, wantSize)
	}
	for name, got := range map[string]uintptr{
		"tproxyPort":           unsafe.Offsetof(p.tproxyPort),
		"controlPlanePid":      unsafe.Offsetof(p.controlPlanePid),
		"dae0Ifindex":          unsafe.Offsetof(p.dae0Ifindex),
		"daeNetnsId":           unsafe.Offsetof(p.daeNetnsId),
		"dae0peerMac":          unsafe.Offsetof(p.dae0peerMac),
		"paddingAfterMac":      unsafe.Offsetof(p.paddingAfterMac),
		"useRedirectPeer":      unsafe.Offsetof(p.useRedirectPeer),
		"hasBpfGetCurrentTask": unsafe.Offsetof(p.hasBpfGetCurrentTask),
		"datapathGeneration":   unsafe.Offsetof(p.datapathGeneration),
		"daeSocketMark":        unsafe.Offsetof(p.daeSocketMark),
	} {
		want, ok := map[string]uintptr{
			"tproxyPort":           0,
			"controlPlanePid":      4,
			"dae0Ifindex":          8,
			"daeNetnsId":           12,
			"dae0peerMac":          16,
			"paddingAfterMac":      22,
			"useRedirectPeer":      24,
			"hasBpfGetCurrentTask": 25,
			"datapathGeneration":   26,
			"daeSocketMark":        28,
		}[name]
		if !ok {
			t.Fatalf("missing expectation for %s", name)
		}
		if got != want {
			t.Fatalf("%s offset = %d, want %d", name, got, want)
		}
	}
}
