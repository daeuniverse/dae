/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
	"unsafe"
)

type memoryLayoutAddr string

func (a memoryLayoutAddr) Network() string { return "memory" }
func (a memoryLayoutAddr) String() string  { return string(a) }

type memoryLayoutConn struct {
	id uint64
}

func (c *memoryLayoutConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *memoryLayoutConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *memoryLayoutConn) Close() error                     { return nil }
func (c *memoryLayoutConn) LocalAddr() net.Addr              { return memoryLayoutAddr("local") }
func (c *memoryLayoutConn) RemoteAddr() net.Addr             { return memoryLayoutAddr("remote") }
func (c *memoryLayoutConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryLayoutConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryLayoutConn) SetWriteDeadline(time.Time) error { return nil }

func TestConnectionMemoryLayout(t *testing.T) {
	const (
		baselineUdpEndpointBytes    = uintptr(1320)
		baselineReplyElementBytes   = uintptr(64)
		baselineBpfUpdateTaskBytes  = uintptr(104)
		maxBpfUpdateTaskBytes       = uintptr(32)
		baselineDnsControllerFacade = uintptr(40)
	)
	endpointBytes := unsafe.Sizeof(UdpEndpoint{})
	replyBytes := unsafe.Sizeof(udpEndpointReply{})
	queueElementBytes := unsafe.Sizeof((*udpEndpointReply)(nil))
	bpfUpdateTaskBytes := unsafe.Sizeof(bpfUpdateTask{})
	dnsControllerFacadeBytes := unsafe.Sizeof(DnsController{})
	tcpRuntimeBytes := unsafe.Sizeof(FlowRuntime{})
	udpRuntimeBytes := unsafe.Sizeof(UDPFlowRuntime{})
	egressLeaseBytes := unsafe.Sizeof(egressRuntimeLease{})
	var emptyContext context.Context
	contextInterfaceBytes := unsafe.Sizeof(emptyContext)
	if endpointBytes >= baselineUdpEndpointBytes {
		t.Fatalf("UdpEndpoint=%d bytes, want below pre-optimization %d", endpointBytes, baselineUdpEndpointBytes)
	}
	if queueElementBytes >= baselineReplyElementBytes {
		t.Fatalf("legacy reply queue element=%d bytes, want below pre-optimization %d", queueElementBytes, baselineReplyElementBytes)
	}
	if bpfUpdateTaskBytes > maxBpfUpdateTaskBytes {
		t.Fatalf("bpfUpdateTask=%d bytes, want at most %d", bpfUpdateTaskBytes, maxBpfUpdateTaskBytes)
	}
	if dnsControllerFacadeBytes >= baselineDnsControllerFacade {
		t.Fatalf("DnsController=%d bytes, want below pre-optimization %d", dnsControllerFacadeBytes, baselineDnsControllerFacade)
	}
	staticLegacyFootprint := endpointBytes + queueElementBytes*udpEndpointReplyQueueSize

	manager := NewSessionManager(context.Background())
	runtime := newEgressRuntime(nil, nil)
	var sequence uint64
	var lifecycleErr error
	tcpLifecycleAllocs := testing.AllocsPerRun(1000, func() {
		sequence++
		flow, err := manager.adoptTCP(
			&memoryLayoutConn{id: sequence},
			nil,
			TcpFlowBinding{},
			runtime,
			nil,
		)
		if err != nil {
			lifecycleErr = err
			return
		}
		_ = flow.Context().Done()
		flow.finish()
	})
	udpEndpoint := &UdpEndpoint{
		poolKey: UdpEndpointKey{
			Src: netip.MustParseAddrPort("192.0.2.1:40000"),
			Dst: netip.MustParseAddrPort("198.51.100.1:443"),
		},
	}
	udpLifecycleAllocs := testing.AllocsPerRun(1000, func() {
		flow, err := manager.adoptUDP(udpEndpoint, UdpFlowBinding{}, runtime)
		if err != nil {
			lifecycleErr = err
			return
		}
		_ = flow.ctx.Done()
		flow.finish()
	})
	contextAllocs := testing.AllocsPerRun(1000, func() {
		ctx, cancel := context.WithCancel(context.Background())
		_ = ctx.Done()
		cancel()
	})
	if lifecycleErr != nil {
		t.Fatalf("flow lifecycle allocation measurement error = %v", lifecycleErr)
	}
	if err := runtime.releaseOwner(); err != nil {
		t.Fatalf("release measured egress runtime: %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("close measured session manager: %v", err)
	}

	t.Logf("UdpEndpoint=%d (was %d) udpEndpointReply=%d legacyQueueElement=%d legacyQueueBacking=%d (was %d) staticLegacyEnvelope=%d FlowRuntime=%d UDPFlowRuntime=%d egressRuntimeLease=%d contextInterfaceSlot=%d contextWithDoneAllocs=%.1f tcpLifecycleAllocs=%.1f udpLifecycleAllocs=%.1f bpfUpdateTask=%d (was %d) DnsController=%d (was %d) UdpFlowBinding=%d TcpFlowBinding=%d",
		endpointBytes,
		baselineUdpEndpointBytes,
		replyBytes,
		queueElementBytes,
		queueElementBytes*udpEndpointReplyQueueSize,
		baselineReplyElementBytes*udpEndpointReplyQueueSize,
		staticLegacyFootprint,
		tcpRuntimeBytes,
		udpRuntimeBytes,
		egressLeaseBytes,
		contextInterfaceBytes,
		contextAllocs,
		tcpLifecycleAllocs,
		udpLifecycleAllocs,
		bpfUpdateTaskBytes,
		baselineBpfUpdateTaskBytes,
		dnsControllerFacadeBytes,
		baselineDnsControllerFacade,
		unsafe.Sizeof(UdpFlowBinding{}),
		unsafe.Sizeof(TcpFlowBinding{}),
	)
}
