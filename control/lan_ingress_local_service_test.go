//go:build linux && dae_bpf_tests

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const currentTCNetnsLookupID = ^uint32(0)

var lanIngressLocalServiceTestSeq atomic.Uint32

func TestTproxyLanIngressL2_BypassesLocalUDPService(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	lanNs := newTransientNetns(t)
	defer func() { _ = lanNs.Close() }()

	clientNs := newTransientNetns(t)
	defer func() { _ = clientNs.Close() }()

	seq := lanIngressLocalServiceTestSeq.Add(1)
	lanIfName := fmt.Sprintf("dut%04xa", seq)
	clientIfName := fmt.Sprintf("dut%04xb", seq)

	createVethPairInNamespaces(t, lanIfName, clientIfName, lanNs, clientNs)

	lanIP := net.ParseIP("198.18.0.1")
	clientIP := net.ParseIP("198.18.0.2")
	configureIPv4Interface(t, lanNs, lanIfName, "198.18.0.1/24")
	configureIPv4Interface(t, clientNs, clientIfName, "198.18.0.2/24")

	lanIfindex := interfaceIndex(t, lanNs, lanIfName)

	serverConn := listenUDPInNetns(t, lanNs, &net.UDPAddr{
		IP:   lanIP,
		Port: 0,
	})
	defer func() { _ = serverConn.Close() }()

	serverAddr, ok := serverConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected UDP local addr type: %T", serverConn.LocalAddr())
	}

	bpfObj := loadLanIngressTestBpfObjects(t, uint32(lanIfindex))
	defer func() { _ = bpfObj.Close() }()

	attachLanIngressFilter(t, lanNs, lanIfName, bpfObj.TproxyLanIngressL2)
	initializeRedirectRoutingFallback(t, bpfObj)

	recvCh := make(chan struct {
		payload []byte
		addr    *net.UDPAddr
		err     error
	}, 1)
	go func() {
		buf := make([]byte, 256)
		_ = serverConn.SetReadDeadline(time.Now().Add(4 * time.Second))
		n, addr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			recvCh <- struct {
				payload []byte
				addr    *net.UDPAddr
				err     error
			}{err: err}
			return
		}
		recvCh <- struct {
			payload []byte
			addr    *net.UDPAddr
			err     error
		}{
			payload: append([]byte(nil), buf[:n]...),
			addr:    addr,
		}
	}()

	payload := []byte("lan-ingress-local-udp-service")
	sendUDPFromNamespace(t, clientNs, &net.UDPAddr{
		IP:   clientIP,
		Port: 0,
	}, serverAddr, payload)

	result := <-recvCh
	if result.err != nil {
		t.Fatalf("read UDP datagram through lan ingress: %v", result.err)
	}
	if got := string(result.payload); got != string(payload) {
		t.Fatalf("unexpected payload: got %q want %q", got, payload)
	}
	if result.addr == nil {
		t.Fatal("missing remote addr")
	}
	if !result.addr.IP.Equal(clientIP) {
		t.Fatalf("unexpected source IP: got %v want %v", result.addr.IP, clientIP)
	}
}

func newTransientNetns(t *testing.T) netns.NsHandle {
	t.Helper()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origin, err := netns.Get()
	if err != nil {
		t.Fatalf("get current netns: %v", err)
	}
	defer func() { _ = origin.Close() }()

	nsHandle, err := netns.New()
	if err != nil {
		t.Fatalf("create transient netns: %v", err)
	}
	if err := netns.Set(origin); err != nil {
		_ = nsHandle.Close()
		t.Fatalf("restore original netns after creation: %v", err)
	}
	return nsHandle
}

func withNetns(t *testing.T, nsHandle netns.NsHandle, fn func() error) {
	t.Helper()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origin, err := netns.Get()
	if err != nil {
		t.Fatalf("get current netns: %v", err)
	}
	defer func() { _ = origin.Close() }()

	if err := netns.Set(nsHandle); err != nil {
		t.Fatalf("switch netns: %v", err)
	}
	defer func() {
		if err := netns.Set(origin); err != nil {
			t.Fatalf("restore original netns: %v", err)
		}
	}()

	if err := fn(); err != nil {
		t.Fatal(err)
	}
}

func createVethPairInNamespaces(t *testing.T, lanIfName, clientIfName string, lanNs, clientNs netns.NsHandle) {
	t.Helper()

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: lanIfName,
		},
		PeerName: clientIfName,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth pair %s/%s: %v", lanIfName, clientIfName, err)
	}

	lanLink, err := netlink.LinkByName(lanIfName)
	if err != nil {
		t.Fatalf("lookup lan veth %s: %v", lanIfName, err)
	}
	clientLink, err := netlink.LinkByName(clientIfName)
	if err != nil {
		t.Fatalf("lookup client veth %s: %v", clientIfName, err)
	}

	if err := netlink.LinkSetNsFd(lanLink, int(lanNs)); err != nil {
		t.Fatalf("move %s to lan netns: %v", lanIfName, err)
	}
	if err := netlink.LinkSetNsFd(clientLink, int(clientNs)); err != nil {
		t.Fatalf("move %s to client netns: %v", clientIfName, err)
	}
}

func configureIPv4Interface(t *testing.T, nsHandle netns.NsHandle, ifName, cidr string) {
	t.Helper()

	withNetns(t, nsHandle, func() error {
		loopback, err := netlink.LinkByName("lo")
		if err != nil {
			return fmt.Errorf("lookup loopback: %w", err)
		}
		if err := netlink.LinkSetUp(loopback); err != nil {
			return fmt.Errorf("bring loopback up: %w", err)
		}

		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("lookup interface %s: %w", ifName, err)
		}

		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			return fmt.Errorf("parse addr %s: %w", cidr, err)
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("assign addr %s to %s: %w", cidr, ifName, err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("bring %s up: %w", ifName, err)
		}
		return nil
	})
}

func interfaceIndex(t *testing.T, nsHandle netns.NsHandle, ifName string) int {
	t.Helper()

	var index int
	withNetns(t, nsHandle, func() error {
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("lookup interface %s: %w", ifName, err)
		}
		index = link.Attrs().Index
		return nil
	})
	return index
}

func listenUDPInNetns(t *testing.T, nsHandle netns.NsHandle, addr *net.UDPAddr) *net.UDPConn {
	t.Helper()

	var (
		conn *net.UDPConn
		err  error
	)
	withNetns(t, nsHandle, func() error {
		conn, err = net.ListenUDP("udp4", addr)
		if err != nil {
			return fmt.Errorf("listen UDP on %v: %w", addr, err)
		}
		return nil
	})
	return conn
}

func sendUDPFromNamespace(t *testing.T, nsHandle netns.NsHandle, localAddr, remoteAddr *net.UDPAddr, payload []byte) {
	t.Helper()

	withNetns(t, nsHandle, func() error {
		conn, err := net.DialUDP("udp4", localAddr, remoteAddr)
		if err != nil {
			return fmt.Errorf("dial UDP %v -> %v: %w", localAddr, remoteAddr, err)
		}
		defer func() { _ = conn.Close() }()

		for range 3 {
			if _, err := conn.Write(payload); err != nil {
				return fmt.Errorf("write UDP payload to %v: %w", remoteAddr, err)
			}
			time.Sleep(100 * time.Millisecond)
		}
		return nil
	})
}

func loadLanIngressTestBpfObjects(t *testing.T, dae0Ifindex uint32) *bpfObjects {
	t.Helper()

	var obj bpfObjects
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelInstruction,
			LogSizeStart: 1 << 20,
		},
	}
	constants := map[string]interface{}{
		"PARAM": bpfDaeParam{
			Dae0Ifindex: dae0Ifindex,
			DaeNetnsId:  currentTCNetnsLookupID,
		},
	}

	if err := loadBpfObjectsWithConstantsAndCustomizer(&obj, opts, constants, disableAllPinnedMapsForTests); err != nil {
		t.Fatalf("load main bpf objects for lan ingress test: %v", err)
	}
	return &obj
}

func attachLanIngressFilter(t *testing.T, nsHandle netns.NsHandle, ifName string, prog *ebpf.Program) {
	t.Helper()

	withNetns(t, nsHandle, func() error {
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("lookup interface %s for tc attach: %w", ifName, err)
		}

		qdisc := buildClsactQdisc(link)
		if err := netlink.QdiscAdd(qdisc); err != nil && err != unix.EEXIST {
			return fmt.Errorf("add clsact qdisc on %s: %w", ifName, err)
		}

		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_INGRESS,
				Handle:    netlink.MakeHandle(0x2026, 1),
				Protocol:  unix.ETH_P_ALL,
				Priority:  1,
			},
			Fd:           prog.FD(),
			Name:         "dae_test_lan_ingress_l2",
			DirectAction: true,
		}
		if err := netlink.FilterAdd(filter); err != nil {
			return fmt.Errorf("attach lan ingress filter to %s: %w", ifName, err)
		}
		return nil
	})
}

func initializeRedirectRoutingFallback(t *testing.T, obj *bpfObjects) {
	t.Helper()

	activeRulesLen := uint32(1)
	if err := obj.RoutingMetaMap.Update(uint32(0), activeRulesLen, ebpf.UpdateAny); err != nil {
		t.Fatalf("initialize routing_meta_map: %v", err)
	}

	matchSet := bpfMatchSet{
		Type:     uint8(consts.MatchType_Fallback),
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}
	if err := obj.RoutingMap.Update(uint32(0), matchSet, ebpf.UpdateAny); err != nil {
		t.Fatalf("initialize fallback routing rule: %v", err)
	}
}
