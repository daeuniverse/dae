/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

type udpReuseSimulationConn struct {
	reads      chan scriptedPacketRead
	readExitCh chan error
	closeCh    chan struct{}
	writeCalls atomic.Int32
	closeCalls atomic.Int32
}

func (c *udpReuseSimulationConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *udpReuseSimulationConn) Write(_ []byte) (int, error) {
	return 0, netproxy.UnsupportedTunnelTypeError
}

func (c *udpReuseSimulationConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	select {
	case <-c.closeCh:
		return 0, netip.AddrPort{}, io.EOF
	case read := <-c.reads:
		if read.err != nil {
			if c.readExitCh != nil {
				select {
				case c.readExitCh <- read.err:
				default:
				}
			}
			return 0, netip.AddrPort{}, read.err
		}
		copy(p, read.data)
		return len(read.data), read.from, nil
	}
}

func (c *udpReuseSimulationConn) WriteTo(b []byte, _ string) (int, error) {
	c.writeCalls.Add(1)
	return len(b), nil
}

func (c *udpReuseSimulationConn) Close() error {
	if c.closeCalls.Add(1) == 1 {
		close(c.closeCh)
	}
	return nil
}

func (c *udpReuseSimulationConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *udpReuseSimulationConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *udpReuseSimulationConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

type countingPacketDialer struct {
	conn  netproxy.Conn
	calls atomic.Int32
}

func (d *countingPacketDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	d.calls.Add(1)
	return d.conn, nil
}

type packetConnFactoryDialer struct {
	factory func() netproxy.Conn
	calls   atomic.Int32
}

func (d *packetConnFactoryDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	d.calls.Add(1)
	return d.factory(), nil
}

type failingPacketDialer struct {
	err   error
	calls atomic.Int32
}

func (d *failingPacketDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	d.calls.Add(1)
	return nil, d.err
}

type scriptedDialResult struct {
	conn netproxy.Conn
	err  error
}

type sequencePacketDialer struct {
	results []scriptedDialResult
	calls   atomic.Int32
}

func (d *sequencePacketDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	call := int(d.calls.Add(1)) - 1
	if call >= len(d.results) {
		call = len(d.results) - 1
	}
	result := d.results[call]
	return result.conn, result.err
}

func newCountingProxyEndpointDialer(protocol, address string, conn netproxy.Conn) (*componentdialer.Dialer, *countingPacketDialer) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	underlay := &countingPacketDialer{conn: conn}
	return componentdialer.NewDialer(
		underlay,
		&componentdialer.GlobalOption{
			Log:           logger,
			CheckInterval: time.Second,
		},
		componentdialer.InstanceOption{DisableCheck: true},
		&componentdialer.Property{
			Property: D.Property{
				Name:     protocol,
				Address:  address,
				Protocol: protocol,
			},
		},
	), underlay
}

func newFactoryProxyEndpointDialer(protocol, address string, factory func() netproxy.Conn) (*componentdialer.Dialer, *packetConnFactoryDialer) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	underlay := &packetConnFactoryDialer{factory: factory}
	return componentdialer.NewDialer(
		underlay,
		&componentdialer.GlobalOption{
			Log:           logger,
			CheckInterval: time.Second,
		},
		componentdialer.InstanceOption{DisableCheck: true},
		&componentdialer.Property{
			Property: D.Property{
				Name:     protocol,
				Address:  address,
				Protocol: protocol,
			},
		},
	), underlay
}

func newFailingProxyEndpointDialer(protocol, address string, err error) (*componentdialer.Dialer, *failingPacketDialer) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	underlay := &failingPacketDialer{err: err}
	return componentdialer.NewDialer(
		underlay,
		&componentdialer.GlobalOption{
			Log:           logger,
			CheckInterval: time.Second,
		},
		componentdialer.InstanceOption{DisableCheck: true},
		&componentdialer.Property{
			Property: D.Property{
				Name:     protocol,
				Address:  address,
				Protocol: protocol,
			},
		},
	), underlay
}

func newSequenceProxyEndpointDialer(protocol, address string, results ...scriptedDialResult) (*componentdialer.Dialer, *sequencePacketDialer) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	underlay := &sequencePacketDialer{results: results}
	return componentdialer.NewDialer(
		underlay,
		&componentdialer.GlobalOption{
			Log:           logger,
			CheckInterval: time.Second,
		},
		componentdialer.InstanceOption{DisableCheck: true},
		&componentdialer.Property{
			Property: D.Property{
				Name:     protocol,
				Address:  address,
				Protocol: protocol,
			},
		},
	), underlay
}

func newUdpReuseSimulationControlPlane(outbound *ob.DialerGroup) *ControlPlane {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	outbounds := make([]*ob.DialerGroup, int(consts.OutboundUserDefinedMin)+1)
	outbounds[consts.OutboundUserDefinedMin] = outbound
	return &ControlPlane{
		log:           logger,
		outbounds:     outbounds,
		soMarkFromDae: 0,
	}
}

func newTestAnyfromPoolWithoutJanitor() *AnyfromPool {
	p := &AnyfromPool{}
	for i := range anyfromPoolShardCount {
		p.shards[i].pool = make(map[netip.AddrPort]*Anyfrom, 16)
	}
	return p
}

func countPooledUdpEndpoints(p *UdpEndpointPool) int {
	total := 0
	for i := range udpEndpointCreateShardCount {
		shard := &p.shards[i]
		shard.mu.RLock()
		total += len(shard.pool)
		shard.mu.RUnlock()
	}
	return total
}

func waitForUdpEndpointReplyState(t *testing.T, key UdpEndpointKey) *UdpEndpoint {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		ue, ok := DefaultUdpEndpointPool.Get(key)
		if ok && ue != nil && ue.hasReply.Load() {
			return ue
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for UDP endpoint to observe upstream reply")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHandlePkt_RepeatedSameIngressReusesSingleUdpEndpoint(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	conn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("52.199.194.44:23002")
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	key := flowDecision.FullConeNatEndpointKey()

	for i := 0; i < 5; i++ {
		if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
			t.Fatalf("handlePkt call %d: %v", i+1, err)
		}
	}

	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls = %d, want 1", got)
	}
	if got := conn.writeCalls.Load(); got != 5 {
		t.Fatalf("WriteTo calls = %d, want 5", got)
	}

	ue, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || ue == nil {
		t.Fatal("expected repeated ingress simulation to keep a pooled UDP endpoint")
	}
	if ue.Dialer != d {
		t.Fatal("expected pooled endpoint to use the original dialer")
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestHandlePkt_ProxyBackedSoftReadLoopExitRedialsFreshEndpoint(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	conn1 := &udpReuseSimulationConn{
		reads:      make(chan scriptedPacketRead, 1),
		readExitCh: make(chan error, 1),
		closeCh:    make(chan struct{}),
	}
	conn2 := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead, 1),
		closeCh: make(chan struct{}),
	}
	var factoryCalls atomic.Int32
	d, underlay := newFactoryProxyEndpointDialer("hysteria2", "proxy.example:443", func() netproxy.Conn {
		call := factoryCalls.Add(1)
		if call == 1 {
			return conn1
		}
		return conn2
	})
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("52.199.194.44:23002")
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}
	payload := []byte{0xaa, 0xbb, 0xcc}
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	key := flowDecision.FullConeNatEndpointKey()

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("first handlePkt: %v", err)
	}

	ue, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || ue == nil {
		t.Fatal("expected first packet to create a pooled UDP endpoint")
	}

	conn1.reads <- scriptedPacketRead{err: io.EOF}

	select {
	case err := <-conn1.readExitCh:
		if err != io.EOF {
			t.Fatalf("soft read exit err = %v, want %v", err, io.EOF)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for simulated soft read exit")
	}

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("second handlePkt after soft read exit: %v", err)
	}

	recreated, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || recreated == nil {
		t.Fatal("expected endpoint to be recreated after proxy-backed soft read exit")
	}
	if recreated == ue {
		t.Fatal("expected second packet to redial instead of reusing the original endpoint")
	}
	if got := underlay.calls.Load(); got != 2 {
		t.Fatalf("DialContext calls after soft read exit = %d, want 2", got)
	}
	if got := conn1.writeCalls.Load(); got != 1 {
		t.Fatalf("first conn WriteTo calls after soft read exit = %d, want 1", got)
	}
	if got := conn2.writeCalls.Load(); got != 1 {
		t.Fatalf("second conn WriteTo calls after redial = %d, want 1", got)
	}
	if got := conn1.closeCalls.Load(); got != 1 {
		t.Fatalf("first conn close calls = %d, want 1", got)
	}
	if err := recreated.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestHandlePkt_ConcurrentSameIngressReusesSingleUdpEndpoint(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	conn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("52.199.194.44:23002")
	payload := []byte{0x11, 0x22, 0x33, 0x44}
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	key := flowDecision.FullConeNatEndpointKey()

	const workers = 64
	const packetsPerWorker = 8

	start := make(chan struct{})
	errCh := make(chan error, workers*packetsPerWorker)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range packetsPerWorker {
				routingResult := &bpfRoutingResult{
					Outbound: uint8(consts.OutboundUserDefinedMin),
				}
				if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
					errCh <- err
				}
			}
		}()
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent handlePkt returned err: %v", err)
		}
	}

	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls = %d, want 1 under concurrent same-flow pressure", got)
	}
	wantWrites := int32(workers * packetsPerWorker)
	if got := conn.writeCalls.Load(); got != wantWrites {
		t.Fatalf("WriteTo calls = %d, want %d", got, wantWrites)
	}
	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != 1 {
		t.Fatalf("pooled endpoint count = %d, want 1", got)
	}

	ue, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || ue == nil {
		t.Fatal("expected pooled endpoint to remain available after concurrent same-flow pressure")
	}
	if err := ue.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestHandlePkt_GameLikeBidirectionalFlowReusesSingleUdpEndpoint(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	conn := &udpReuseSimulationConn{
		reads:      make(chan scriptedPacketRead, 16),
		readExitCh: make(chan error, 1),
		closeCh:    make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("52.199.194.44:23002")
	from := mustParseAddrPort("52.199.194.44:23002")
	payload := []byte{0x10, 0x20, 0x30, 0x40}
	key := UdpEndpointKey{Src: src}

	ue, isNew, err := DefaultUdpEndpointPool.GetOrCreate(key, &UdpEndpointOptions{
		Handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
		NatTimeout: DefaultNatTimeout,
		Log:        logger,
		GetDialOption: func(ctx context.Context) (*DialOption, error) {
			return &DialOption{
				Target:      dst.String(),
				Dialer:      d,
				Outbound:    newTestFixedOutboundGroup(d),
				Network:     "udp",
				NetworkType: &componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, UdpHealthDomain: componentdialer.UdpHealthDomainData},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("GetOrCreate initial endpoint: %v", err)
	}
	if !isNew {
		t.Fatal("expected initial GetOrCreate to create a new endpoint")
	}

	for i := 0; i < 6; i++ {
		if _, err := ue.WriteTo(payload, dst.String()); err != nil {
			t.Fatalf("WriteTo warmup #%d: %v", i+1, err)
		}
		conn.reads <- scriptedPacketRead{data: []byte{byte(i + 1)}, from: from}
	}

	ue = waitForUdpEndpointReplyState(t, key)

	for i := 0; i < 12; i++ {
		if _, err := ue.WriteTo(payload, dst.String()); err != nil {
			t.Fatalf("WriteTo established #%d: %v", i+1, err)
		}
		conn.reads <- scriptedPacketRead{data: []byte{0x90, byte(i)}, from: from}
	}

	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls = %d, want 1 for stable game-like bidirectional flow", got)
	}
	if got := conn.writeCalls.Load(); got != 18 {
		t.Fatalf("WriteTo calls = %d, want 18", got)
	}

	ue, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || ue == nil {
		t.Fatal("expected bidirectional game-like flow to keep a pooled UDP endpoint")
	}
	if !ue.hasReply.Load() {
		t.Fatal("expected endpoint to enter established state after upstream replies")
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestHandlePkt_GameLikeFlowDoesNotRedialDuringIntermittentReplyBursts(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	conn := &udpReuseSimulationConn{
		reads:      make(chan scriptedPacketRead, 16),
		readExitCh: make(chan error, 1),
		closeCh:    make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("52.199.194.44:23002")
	from := mustParseAddrPort("52.199.194.44:23002")
	payload := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	key := UdpEndpointKey{Src: src}

	ue, isNew, err := DefaultUdpEndpointPool.GetOrCreate(key, &UdpEndpointOptions{
		Handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
		NatTimeout: DefaultNatTimeout,
		Log:        logger,
		GetDialOption: func(ctx context.Context) (*DialOption, error) {
			return &DialOption{
				Target:      dst.String(),
				Dialer:      d,
				Outbound:    newTestFixedOutboundGroup(d),
				Network:     "udp",
				NetworkType: &componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, UdpHealthDomain: componentdialer.UdpHealthDomainData},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("GetOrCreate initial endpoint: %v", err)
	}
	if !isNew {
		t.Fatal("expected initial GetOrCreate to create a new endpoint")
	}

	for i := 0; i < 3; i++ {
		if _, err := ue.WriteTo(payload, dst.String()); err != nil {
			t.Fatalf("warmup WriteTo #%d: %v", i+1, err)
		}
		conn.reads <- scriptedPacketRead{data: []byte{0x01, byte(i)}, from: from}
	}

	ue = waitForUdpEndpointReplyState(t, key)

	for i := 0; i < 20; i++ {
		if _, err := ue.WriteTo(payload, dst.String()); err != nil {
			t.Fatalf("steady-state WriteTo #%d: %v", i+1, err)
		}
		if i%5 == 0 {
			conn.reads <- scriptedPacketRead{data: []byte{0x02, byte(i)}, from: from}
		}
	}

	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls = %d, want 1 for intermittent-reply game flow", got)
	}
	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != 1 {
		t.Fatalf("pooled endpoint count = %d, want 1", got)
	}

	ue, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || ue == nil {
		t.Fatal("expected intermittent-reply game flow to keep a pooled endpoint")
	}
	if err := ue.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestHandlePkt_ShadowsocksGameLikeBidirectionalFlowReusesSingleUdpEndpoint(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	conn := &udpReuseSimulationConn{
		reads:      make(chan scriptedPacketRead, 16),
		readExitCh: make(chan error, 1),
		closeCh:    make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("shadowsocks", "proxy.example:443", conn)
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("52.199.194.44:23002")
	from := mustParseAddrPort("52.199.194.44:23002")
	payload := []byte{0x21, 0x22, 0x23, 0x24}
	key := UdpEndpointKey{Src: src}

	ue, isNew, err := DefaultUdpEndpointPool.GetOrCreate(key, &UdpEndpointOptions{
		Handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
		NatTimeout: DefaultNatTimeout,
		Log:        logger,
		GetDialOption: func(ctx context.Context) (*DialOption, error) {
			return &DialOption{
				Target:      dst.String(),
				Dialer:      d,
				Outbound:    newTestFixedOutboundGroup(d),
				Network:     "udp",
				NetworkType: &componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, UdpHealthDomain: componentdialer.UdpHealthDomainData},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("GetOrCreate initial endpoint: %v", err)
	}
	if !isNew {
		t.Fatal("expected initial GetOrCreate to create a new endpoint")
	}

	for i := 0; i < 5; i++ {
		if _, err := ue.WriteTo(payload, dst.String()); err != nil {
			t.Fatalf("WriteTo warmup #%d: %v", i+1, err)
		}
		conn.reads <- scriptedPacketRead{data: []byte{0x30, byte(i)}, from: from}
	}

	ue = waitForUdpEndpointReplyState(t, key)

	for i := 0; i < 10; i++ {
		if _, err := ue.WriteTo(payload, dst.String()); err != nil {
			t.Fatalf("WriteTo established #%d: %v", i+1, err)
		}
		conn.reads <- scriptedPacketRead{data: []byte{0x40, byte(i)}, from: from}
	}

	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls = %d, want 1 for stable Shadowsocks game flow", got)
	}
	if got := conn.writeCalls.Load(); got != 15 {
		t.Fatalf("WriteTo calls = %d, want 15", got)
	}

	ue, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || ue == nil {
		t.Fatal("expected Shadowsocks game flow to keep a pooled UDP endpoint")
	}
	if !ue.hasReply.Load() {
		t.Fatal("expected Shadowsocks endpoint to enter established state after upstream replies")
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestHandlePkt_ConcurrentManyIngressesReusePerFlow(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	d, underlay := newFactoryProxyEndpointDialer("hysteria2", "proxy.example:443", func() netproxy.Conn {
		return &udpReuseSimulationConn{
			reads:   make(chan scriptedPacketRead),
			closeCh: make(chan struct{}),
		}
	})
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	dst := mustParseAddrPort("52.199.194.44:23002")
	payload := []byte{0x51, 0x52, 0x53, 0x54}

	const flows = 96
	const packetsPerFlow = 6

	start := make(chan struct{})
	errCh := make(chan error, flows*packetsPerFlow)
	var wg sync.WaitGroup
	for i := range flows {
		src := mustParseAddrPort(fmt.Sprintf("192.168.89.3:%d", 30000+i))
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
				}
			}
		}(src, flowDecision)
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("high-churn handlePkt returned err: %v", err)
		}
	}

	if got := underlay.calls.Load(); got != flows {
		t.Fatalf("DialContext calls = %d, want %d under high-churn pressure", got, flows)
	}
	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != flows {
		t.Fatalf("pooled endpoint count = %d, want %d", got, flows)
	}

	for i := range flows {
		src := mustParseAddrPort(fmt.Sprintf("192.168.89.3:%d", 30000+i))
		key := ClassifyUdpFlow(src, dst, payload).FullConeNatEndpointKey()
		ue, ok := DefaultUdpEndpointPool.Get(key)
		if !ok || ue == nil {
			t.Fatalf("expected pooled endpoint for flow %d (%v)", i, src)
		}
	}
}

func TestAnyfromPool_ConcurrentExistingSocketReusesCachedBind(t *testing.T) {
	pool := newTestAnyfromPoolWithoutJanitor()
	lAddr := mustParseAddrPort("127.0.0.1:5353")
	af := &Anyfrom{
		ttl: AnyfromTimeout,
	}
	af.expiresAtNano.Store(time.Now().Add(AnyfromTimeout).UnixNano())

	shard := pool.shardFor(lAddr)
	shard.mu.Lock()
	shard.pool[lAddr] = af
	shard.mu.Unlock()

	const callers = 128

	start := make(chan struct{})
	errCh := make(chan error, callers)
	connCh := make(chan *Anyfrom, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			conn, isNew, err := pool.GetOrCreate(lAddr, AnyfromTimeout)
			if err != nil {
				errCh <- err
				return
			}
			if isNew {
				errCh <- fmt.Errorf("GetOrCreate reported isNew for cached anyfrom entry")
				return
			}
			connCh <- conn
		}()
	}

	close(start)
	wg.Wait()
	close(errCh)
	close(connCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("GetOrCreate returned err: %v", err)
		}
	}
	for conn := range connCh {
		if conn != af {
			t.Fatal("expected all callers to reuse the same cached anyfrom socket")
		}
	}
}

func TestAnyfromPool_ConcurrentFailedBindEntrySuppressesRetryStorm(t *testing.T) {
	pool := newTestAnyfromPoolWithoutJanitor()
	lAddr := mustParseAddrPort("127.0.0.1:5353")
	failed := &Anyfrom{
		ttl: 2 * time.Second,
	}
	failed.failed.Store(true)
	failed.expiresAtNano.Store(time.Now().Add(2 * time.Second).UnixNano())

	shard := pool.shardFor(lAddr)
	shard.mu.Lock()
	shard.pool[lAddr] = failed
	shard.mu.Unlock()

	const callers = 128

	start := make(chan struct{})
	errCh := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			conn, isNew, err := pool.GetOrCreate(lAddr, AnyfromTimeout)
			if !stderrors.Is(err, ErrAnyfromBindFailed) {
				errCh <- fmt.Errorf("GetOrCreate err = %v, want %v", err, ErrAnyfromBindFailed)
				return
			}
			if conn != nil {
				errCh <- fmt.Errorf("GetOrCreate returned non-nil conn for failed bind entry")
				return
			}
			if isNew {
				errCh <- fmt.Errorf("GetOrCreate reported isNew for failed bind hot path")
			}
		}()
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("failed-bind hot path returned unexpected result: %v", err)
		}
	}

	shard.mu.RLock()
	current := shard.pool[lAddr]
	shard.mu.RUnlock()
	if current != failed {
		t.Fatal("expected failed bind cache entry to remain unchanged during retry storm suppression")
	}
}
