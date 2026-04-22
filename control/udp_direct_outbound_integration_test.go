/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

type udpCaptureResult struct {
	addrs []netip.AddrPort
	err   error
}

func newSilentDialerGlobalOption() *componentdialer.GlobalOption {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return &componentdialer.GlobalOption{
		Log:           logger,
		CheckInterval: time.Second,
	}
}

func mustListenLoopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(loopback): %v", err)
	}
	return conn
}

func mustListenLoopbackUDP6(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Skipf("ListenUDP(loopback ipv6): %v", err)
	}
	return conn
}

func startUDPSenderCapture(t *testing.T, conn *net.UDPConn, want int) <-chan udpCaptureResult {
	t.Helper()
	resultCh := make(chan udpCaptureResult, 1)
	go func() {
		defer close(resultCh)

		buf := make([]byte, 2048)
		seen := make([]netip.AddrPort, 0, want)
		for range want {
			if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				resultCh <- udpCaptureResult{err: err}
				return
			}
			_, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				resultCh <- udpCaptureResult{err: err}
				return
			}
			seen = append(seen, from)
		}
		resultCh <- udpCaptureResult{addrs: seen}
	}()
	return resultCh
}

func uniqueUDPPorts(addrs []netip.AddrPort) map[uint16]struct{} {
	ports := make(map[uint16]struct{}, len(addrs))
	for _, addr := range addrs {
		ports[addr.Port()] = struct{}{}
	}
	return ports
}

func newDirectFullconeTestControlPlane(t *testing.T) *ControlPlane {
	t.Helper()
	globalOption := newSilentDialerGlobalOption()
	underlay, property := componentdialer.NewDirectDialer(globalOption, true)
	d := componentdialer.NewDialer(underlay, globalOption, componentdialer.InstanceOption{DisableCheck: true}, property)
	return newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))
}

func sendDirectFullconeFlowPackets(t *testing.T, cp *ControlPlane, src, dst netip.AddrPort, payload []byte, count int) {
	t.Helper()
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	for i := range count {
		routingResult := &bpfRoutingResult{
			Outbound: uint8(consts.OutboundUserDefinedMin),
		}
		if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
			t.Fatalf("handlePkt(%d): %v", i+1, err)
		}
	}
}

func TestDirectFullconeDialer_RepeatedDialsAllocateFreshLocalPorts(t *testing.T) {
	server := mustListenLoopbackUDP(t)
	defer func() { _ = server.Close() }()

	const dials = 12
	resultCh := startUDPSenderCapture(t, server, dials)

	globalOption := newSilentDialerGlobalOption()
	d, _ := componentdialer.NewDirectDialer(globalOption, true)

	var conns []io.Closer
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()

	target := server.LocalAddr().String()
	for i := range dials {
		conn, err := d.DialContext(context.Background(), "udp", target)
		if err != nil {
			t.Fatalf("DialContext(%d): %v", i+1, err)
		}
		conns = append(conns, conn)
		if _, err := conn.Write([]byte{byte(i)}); err != nil {
			t.Fatalf("Write(%d): %v", i+1, err)
		}
	}

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("capture error: %v", result.err)
	}
	if got := len(uniqueUDPPorts(result.addrs)); got != dials {
		t.Fatalf("unique sender ports = %d, want %d", got, dials)
	}
}

func TestHandlePkt_DirectFullconeOutboundReusesStableLocalPortPerFlow(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	server := mustListenLoopbackUDP(t)
	defer func() { _ = server.Close() }()

	const packets = 8
	resultCh := startUDPSenderCapture(t, server, packets)

	cp := newDirectFullconeTestControlPlane(t)

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := server.LocalAddr().(*net.UDPAddr).AddrPort()
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	key := flowDecision.FullConeNatEndpointKey()

	sendDirectFullconeFlowPackets(t, cp, src, dst, payload, packets)

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("capture error: %v", result.err)
	}
	if got := len(uniqueUDPPorts(result.addrs)); got != 1 {
		t.Fatalf("unique sender ports for one flow = %d, want 1", got)
	}

	ue, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || ue == nil {
		t.Fatal("expected direct fullcone flow to keep a pooled UDP endpoint")
	}
	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != 1 {
		t.Fatalf("pooled endpoint count = %d, want 1", got)
	}
}

func TestHandlePkt_DirectFullconeOutboundReusesStableLocalPortPerIPv6Flow(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	server := mustListenLoopbackUDP6(t)
	defer func() { _ = server.Close() }()

	const packets = 8
	resultCh := startUDPSenderCapture(t, server, packets)

	cp := newDirectFullconeTestControlPlane(t)

	src := mustParseAddrPort("[2001:db8::89]:42687")
	dst := server.LocalAddr().(*net.UDPAddr).AddrPort()
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	key := flowDecision.FullConeNatEndpointKey()

	sendDirectFullconeFlowPackets(t, cp, src, dst, payload, packets)

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("capture error: %v", result.err)
	}
	if got := len(uniqueUDPPorts(result.addrs)); got != 1 {
		t.Fatalf("unique sender ports for one ipv6 flow = %d, want 1", got)
	}

	ue, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || ue == nil {
		t.Fatal("expected direct fullcone ipv6 flow to keep a pooled UDP endpoint")
	}
	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != 1 {
		t.Fatalf("pooled endpoint count = %d, want 1", got)
	}
}

func TestHandlePkt_DirectFullconeConcurrentManyFlowsAllocateOneLocalPortPerFlow(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	server := mustListenLoopbackUDP(t)
	defer func() { _ = server.Close() }()

	const flows = 24
	const packetsPerFlow = 4
	resultCh := startUDPSenderCapture(t, server, flows*packetsPerFlow)

	cp := newDirectFullconeTestControlPlane(t)
	dst := server.LocalAddr().(*net.UDPAddr).AddrPort()
	payload := []byte{0xfa, 0xce, 0xb0, 0x0c}

	start := make(chan struct{})
	errCh := make(chan error, flows)
	var wg sync.WaitGroup
	for i := range flows {
		src := mustParseAddrPort(net.JoinHostPort("192.168.89.3", strconv.Itoa(31000+i)))
		flowDecision := ClassifyUdpFlow(src, dst, payload)

		wg.Add(1)
		go func(src netip.AddrPort, flowDecision UdpFlowDecision) {
			defer wg.Done()
			<-start
			for range packetsPerFlow {
				routingResult := &bpfRoutingResult{
					Outbound: uint8(consts.OutboundUserDefinedMin),
				}
				if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
					errCh <- err
					return
				}
			}
		}(src, flowDecision)
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent direct/fullcone handlePkt err: %v", err)
		}
	}

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("capture error: %v", result.err)
	}
	if got := len(uniqueUDPPorts(result.addrs)); got != flows {
		t.Fatalf("unique sender ports under direct/fullcone multi-flow pressure = %d, want %d", got, flows)
	}
	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != flows {
		t.Fatalf("pooled endpoint count = %d, want %d", got, flows)
	}
}

func TestHandlePkt_DirectFullconeReloadReusesSingleNewLocalPortPerFlow(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	server := mustListenLoopbackUDP(t)
	defer func() { _ = server.Close() }()

	const packetsPerPhase = 4
	resultCh := startUDPSenderCapture(t, server, packetsPerPhase*2)

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := server.LocalAddr().(*net.UDPAddr).AddrPort()
	payload := []byte{0xca, 0xfe, 0xba, 0xbe}

	cp1 := newDirectFullconeTestControlPlane(t)
	sendDirectFullconeFlowPackets(t, cp1, src, dst, payload, packetsPerPhase)

	DefaultUdpEndpointPool.Reset()

	cp2 := newDirectFullconeTestControlPlane(t)
	sendDirectFullconeFlowPackets(t, cp2, src, dst, payload, packetsPerPhase)

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("capture error: %v", result.err)
	}

	before := result.addrs[:packetsPerPhase]
	after := result.addrs[packetsPerPhase:]
	if got := len(uniqueUDPPorts(before)); got != 1 {
		t.Fatalf("unique sender ports before reload = %d, want 1", got)
	}
	if got := len(uniqueUDPPorts(after)); got != 1 {
		t.Fatalf("unique sender ports after reload = %d, want 1", got)
	}
	if got := len(uniqueUDPPorts(result.addrs)); got > 2 {
		t.Fatalf("unique sender ports across reload = %d, want <= 2", got)
	}
	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != 1 {
		t.Fatalf("pooled endpoint count after reload = %d, want 1", got)
	}
}
