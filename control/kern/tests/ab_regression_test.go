//go:build linux && dae_bpf_tests

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package tests

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"
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
		// The datapath may only pass a packet through when the host socket it
		// finds is bound to the packet's destination address (1.1.1.1 for the
		// packet this case generates). A wildcard-bound socket answers for any
		// destination, so its presence is no proof that the packet was meant
		// for this host.
		bindTestUDP(t, fmt.Sprintf("1.1.1.1:%d", abTestHostUDPPort))

		markAllOutboundsAlive(t, obj)
		key := uint32(0)
		activeRulesLen := uint32(testMaxMatchSetLen)
		if err := obj.RoutingMetaMap.Update(key, activeRulesLen, ebpf.UpdateAny); err != nil {
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
			t.Fatalf("host-netns UDP listener bound to the destination was not passed through: status=%d", status)
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

const (
	tcActOK       uint32 = 0
	tcActShot     uint32 = 2
	tcActRedirect uint32 = 7

	// ipv6Freebind is IPV6_FREEBIND (linux/ipv6.h); the syscall package only
	// defines the IPv4 spelling.
	ipv6Freebind = 78
)

// bindTestUDP binds a host-netns UDP socket for the bypass matrix. The address
// may be wildcard or unreal (192.0.2.1 / 2001:db8:1::1); IP_FREEBIND lets the
// test place a "service" on a documentation address without touching the host's
// addresses, and the datapath only compares the bound address with the packet's
// destination.
func bindTestUDP(t *testing.T, addr string) {
	t.Helper()

	network, freebindLevel, freebindOpt := "udp4", syscall.IPPROTO_IP, syscall.IP_FREEBIND
	if strings.HasPrefix(addr, "[") { // the IPv6 spelling is bracketed
		network, freebindLevel, freebindOpt = "udp6", syscall.IPPROTO_IPV6, ipv6Freebind
	}

	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var soErr error
		if err := c.Control(func(fd uintptr) {
			// SO_REUSEADDR lets the test place a wildcard :53 listener next
			// to the host's loopback-only stub resolver; the freebind option
			// lets it bind a documentation address.
			soErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			if soErr != nil {
				return
			}
			soErr = syscall.SetsockoptInt(int(fd), freebindLevel, freebindOpt, 1)
		}); err != nil {
			return err
		}
		return soErr
	}}
	pc, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		t.Fatalf("bind host-netns UDP listener on %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = pc.Close() })
}

// TestABLanIngressLocalServiceBypass pins which host-netns UDP sockets may
// swallow a LAN-ingress packet before routing.
//
// The datapath passes a packet through when a matching local socket exists. The
// only case that justifies it is a service bound to the packet's exact
// destination address (NAT loopback); a wildcard-bound socket must not capture
// traffic addressed elsewhere, and DNS must always reach the routing pass so the
// router can punt it to the control plane. The runner installs a live proxy
// fallback, so TC_ACT_OK means "passed through" and TC_ACT_REDIRECT means
// "routed".
func TestABLanIngressLocalServiceBypass(t *testing.T) {
	obj := loadABRegressionObjects(t)
	defer obj.Close()

	markAllOutboundsAlive(t, obj)
	if err := obj.RoutingMetaMap.Update(uint32(0), uint32(testMaxMatchSetLen), ebpf.UpdateAny); err != nil {
		t.Fatalf("initialize routing metadata: %v", err)
	}

	const (
		servicePort = 54322
		serviceAddr = "192.0.2.1"
	)

	cases := []struct {
		name       string
		bind       string
		program    *ebpf.Program
		runner     *ebpf.Program // defaults to the proxy-fallback runner
		wantStatus uint32
	}{
		{
			name:    "service bound to the destination address keeps the NAT-loopback pass-through",
			bind:    fmt.Sprintf("%s:%d", serviceAddr, servicePort),
			program: obj.TestAbLanIngressUdpServiceLocalPktgen, wantStatus: tcActOK,
		},
		{
			name:    "a wildcard-bound service does not swallow a remote destination",
			bind:    fmt.Sprintf("0.0.0.0:%d", servicePort),
			program: obj.TestAbLanIngressUdpServiceRemotePktgen, wantStatus: tcActRedirect,
		},
		{
			name:    "a wildcard-bound service does not swallow a local destination",
			bind:    fmt.Sprintf("0.0.0.0:%d", servicePort),
			program: obj.TestAbLanIngressUdpWildcardLocalServicePktgen, wantStatus: tcActRedirect,
		},
		{
			name:    "no listener routes the packet",
			program: obj.TestAbLanIngressUdpNoListenerPktgen, wantStatus: tcActRedirect,
		},
		{
			name:    "a wildcard-bound DNS listener does not swallow a LAN query",
			bind:    "0.0.0.0:53",
			program: obj.TestAbLanIngressUdpDnsLocalPktgen, wantStatus: tcActRedirect,
		},
		{
			name:    "a DNS listener bound to the destination address does not swallow a LAN query",
			bind:    "192.0.2.1:53",
			program: obj.TestAbLanIngressUdpDnsLocalPktgen, wantStatus: tcActRedirect,
		},
		{
			name:    "a LAN query to a remote resolver is routed",
			bind:    "0.0.0.0:53",
			program: obj.TestAbLanIngressUdpDnsRemotePktgen, wantStatus: tcActRedirect,
		},
		{
			name:    "an IPv6 service bound to the destination address keeps the NAT-loopback pass-through",
			bind:    "[2001:db8:1::1]:54322",
			program: obj.TestAbLanIngressUdp6ServiceLocalPktgen, wantStatus: tcActOK,
		},
		{
			name:    "an IPv6 wildcard-bound service does not swallow a local destination",
			bind:    "[::]:54322",
			program: obj.TestAbLanIngressUdp6WildcardLocalServicePktgen, wantStatus: tcActRedirect,
		},
		{
			name:    "an IPv6 wildcard-bound DNS listener does not swallow a LAN query",
			bind:    "[::]:53",
			program: obj.TestAbLanIngressUdp6DnsLocalPktgen, wantStatus: tcActRedirect,
		},
		{
			name:    "a user block rule applies to a wildcard-bound local service",
			bind:    fmt.Sprintf("0.0.0.0:%d", servicePort),
			program: obj.TestAbLanIngressUdpBlockRulePktgen,
			runner:  obj.TestAbLanIngressUdpLocalServiceBlockRunner, wantStatus: tcActShot,
		},
		{
			name:    "a user block rule does not apply to a service bound to the destination address",
			bind:    fmt.Sprintf("%s:%d", serviceAddr, servicePort),
			program: obj.TestAbLanIngressUdpServiceLocalPktgen,
			runner:  obj.TestAbLanIngressUdpLocalServiceBlockRunner, wantStatus: tcActOK,
		},
		{
			name:    "the default direct fallback still delivers a wildcard-bound local service",
			bind:    fmt.Sprintf("0.0.0.0:%d", servicePort),
			program: obj.TestAbLanIngressUdpDirectFallbackPktgen,
			runner:  obj.TestAbLanIngressUdpLocalServiceDirectRunner, wantStatus: tcActOK,
		},
		{
			name:    "a must_direct rule still hands DNS to a wildcard-bound local resolver",
			bind:    "0.0.0.0:53",
			program: obj.TestAbLanIngressUdpDnsLocalPktgen,
			runner:  obj.TestAbLanIngressUdpLocalServiceDirectRunner, wantStatus: tcActOK,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.bind != "" {
				bindTestUDP(t, c.bind)
			}

			status, data, ctx, err := runBpfProgram(c.program, make([]byte, 4096-256-320), make([]byte, 256))
			if err != nil || status != 0 {
				t.Fatalf("packet generation: status=%d err=%v", status, err)
			}

			runner := c.runner
			if runner == nil {
				runner = obj.TestAbLanIngressUdpLocalServiceRunner
			}

			status, _, _, err = runBpfProgram(runner, data, ctx)
			if err != nil {
				t.Fatalf("LAN ingress program: %v", err)
			}
			t.Logf("LAN ingress status = %d (want %d)", status, c.wantStatus)
			if status != c.wantStatus {
				t.Fatalf("LAN ingress status = %d, want %d", status, c.wantStatus)
			}
		})
	}
}
