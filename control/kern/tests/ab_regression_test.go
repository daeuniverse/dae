//go:build linux && dae_bpf_tests

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package tests

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
)

const abTestHostUDPPort = 54321

func loadABRegressionObjects(t *testing.T) *bpftestObjects {
	t.Helper()

	return loadABRegressionObjectsWithMark(t, 0x200)
}

// loadABRegressionObjectsWithMark loads the ab_test programs with the given
// dae socket mark. A mark of 0 exercises the "so_mark was never injected"
// fallback of pid_is_control_plane, which needs its own object because PARAM
// is frozen at load time.
func loadABRegressionObjectsWithMark(t *testing.T, soMark uint32) *bpftestObjects {
	t.Helper()

	obj := &bpftestObjects{}
	spec, err := loadBpftest()
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	if err = disableAllPinnedMapsForTests(spec); err != nil {
		t.Fatalf("disable pinned maps: %v", err)
	}
	param := struct {
		tproxyPort           uint32
		controlPlanePid      uint32
		dae0Ifindex          uint32
		daeNetnsId           uint32
		dae0peerMac          [6]byte
		paddingAfterMac      [2]uint8
		useRedirectPeer      uint8
		hasBpfGetCurrentTask uint8
		datapathGeneration   uint16
		daeSocketMark        uint32
	}{
		datapathGeneration: 41,
		daeSocketMark:      soMark,
	}
	if err = spec.Variables["PARAM"].Set(param); err != nil {
		t.Fatalf("set PARAM: %v", err)
	}
	if err = spec.LoadAndAssign(obj, &ebpf.CollectionOptions{}); err != nil {
		t.Fatalf("load objects: %v", err)
	}
	return obj
}

func TestABRegression(t *testing.T) {
	obj := loadABRegressionObjects(t)
	defer obj.Close()

	t.Run("custom mark excludes foreign bit 8", func(t *testing.T) {
		data := make([]byte, 4096-256-320)
		ctx := make([]byte, 256)
		status, _, _, err := runBpfProgram(obj.TestAbControlPlaneCustomMark, data, ctx)
		if err != nil || status != 0 {
			t.Fatalf("custom-mark policy: status=%d err=%v", status, err)
		}
	})

	t.Run("IPv6 AH UDP parse", func(t *testing.T) {
		data := make([]byte, 4096-256-320)
		ctx := make([]byte, 256)
		status, _, _, err := runBpfProgram(obj.TestAbIpv6AhUdpParse, data, ctx)
		if err != nil || status != 0 {
			t.Fatalf("AH parse: status=%d err=%v", status, err)
		}
	})

	t.Run("raw header bytes drive IPv4/TCP parsing", func(t *testing.T) {
		runAbCheckProgram(t, obj.TestAbRawHeaderParse, "raw header parse")
	})

	t.Run("reply binding is single-writer while fresh", func(t *testing.T) {
		runAbCheckProgram(t, obj.TestAbRedirectRebindLock, "redirect rebind lock")
	})

	t.Run("same-tuple SYN cannot rewrite a live flow", func(t *testing.T) {
		runAbCheckProgram(t, obj.TestAbSynRebindLock, "syn rebind lock")
	})

	t.Run("same-tuple SYN keeps a live flow only inside its routing epoch", func(t *testing.T) {
		runAbCheckProgram(t, obj.TestAbSynRebindEpochChange, "syn rebind epoch change")
	})

	t.Run("same-tuple SYN reroutes an entry written by another datapath", func(t *testing.T) {
		runAbCheckProgram(t, obj.TestAbSynRebindGenerationChange, "syn rebind generation change")
	})

	t.Run("reply path refreshes a binding only for its own publisher", func(t *testing.T) {
		runAbCheckProgram(t, obj.TestAbRedirectReplyRefreshPublisher, "redirect reply refresh publisher")
	})

	t.Run("stateless established TCP is counted", func(t *testing.T) {
		runAbCheckProgram(t, obj.TestAbStatelessTcpPassthrough, "stateless TCP passthrough")
	})

	t.Run("unsolicited WAN-ingress UDP creates no state", func(t *testing.T) {
		runAbCheckProgram(t, obj.TestAbUnsolicitedUdpWanIngress, "unsolicited UDP")
	})

	t.Run("fragment tail is counted and forwarded", func(t *testing.T) {
		runAbCheckProgram(t, obj.TestAbFragTailPassthrough, "fragment tail")
	})

	t.Run("unsupported L4 and non-IP parse codes split", func(t *testing.T) {
		runAbCheckProgram(t, obj.TestAbParseReturnCodeSplit, "parse return code split")
	})

	t.Run("LAN ingress host UDP listener passthrough", func(t *testing.T) {
		listener, err := net.ListenUDP("udp4", &net.UDPAddr{
			IP:   net.IPv4zero,
			Port: abTestHostUDPPort,
		})
		if err != nil {
			t.Fatalf("bind host-netns UDP listener: %v", err)
		}
		defer func() { _ = listener.Close() }()

		markAllOutboundsAlive(t, obj)
		key := uint32(0)
		activeRulesLen := uint32(testMaxMatchSetLen)
		if err = obj.RoutingMetaMap.Update(key, activeRulesLen, ebpf.UpdateAny); err != nil {
			t.Fatalf("initialize routing metadata: %v", err)
		}

		data := make([]byte, 4096-256-320)
		ctx := make([]byte, 256)
		status, data, ctx, err := runBpfProgram(obj.TestAbLanIngressUdpHostListenerPktgen, data, ctx)
		if err != nil || status != 0 {
			t.Fatalf("packet generation: status=%d err=%v", status, err)
		}
		status, _, _, err = runBpfProgram(obj.TestAbLanIngressUdpHostListener, data, ctx)
		if err != nil {
			t.Fatalf("LAN ingress program: %v", err)
		}
		if status != 0 {
			t.Fatalf("host-netns UDP listener was not passed through: status=%d", status)
		}
	})

	t.Run("UDP refresh bypasses routing args scratch", func(t *testing.T) {
		runAbCheckProgram(t, obj.TestAbUdpRefreshBypassesRoutingArgs, "UDP refresh scratch bypass")
	})

	t.Run("cookie PID timestamp refresh is lazy", func(t *testing.T) {
		runAbCheckProgram(t, obj.TestAbCookiePidLazyRefresh, "cookie PID lazy refresh")
	})
}

// TestABControlPlaneSockmarkFallback pins the last-resort fallback of
// pid_is_control_plane: without an injected so_mark the reserved-bit test is
// used and counted. It needs a separate object load because PARAM is frozen at
// load time.
func TestABControlPlaneSockmarkFallback(t *testing.T) {
	obj := loadABRegressionObjectsWithMark(t, 0)
	defer obj.Close()

	runAbCheckProgram(t, obj.TestAbControlPlaneSockmarkFallback, "sockmark fallback")
}

// runAbCheckProgram runs a self-checking tc/ab_test program, which returns 0
// on success and a case-specific non-zero code on failure.
func runAbCheckProgram(t *testing.T, prog *ebpf.Program, name string) {
	t.Helper()

	if prog == nil {
		t.Fatalf("%s: program missing from the compiled object", name)
	}
	data := make([]byte, 4096-256-320)
	ctx := make([]byte, 256)
	status, _, _, err := runBpfProgram(prog, data, ctx)
	if err != nil {
		t.Fatalf("%s: run: %v", name, err)
	}
	if status != 0 {
		t.Fatalf("%s: self-check failed with code %d", name, status)
	}
}
