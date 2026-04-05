/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

type scriptedPacketRead struct {
	data []byte
	from netip.AddrPort
	err  error
}

type scriptedPacketConn struct {
	reads       chan scriptedPacketRead
	writeErr    error
	writeN      int
	forceWriteN bool
	closeCh     chan struct{}
	closeCalls  atomic.Int32
}

type scriptedTransportPacketConn struct {
	*scriptedPacketConn
	transportDone chan struct{}
}

type scriptedDialer struct {
	conns []netproxy.Conn
	idx   atomic.Int32
}

func (d *scriptedDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	if len(d.conns) == 0 {
		return nil, io.EOF
	}
	i := int(d.idx.Add(1)) - 1
	if i >= len(d.conns) {
		i = len(d.conns) - 1
	}
	return d.conns[i], nil
}

func (c *scriptedPacketConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *scriptedPacketConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (c *scriptedPacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	select {
	case <-c.closeCh:
		return 0, netip.AddrPort{}, io.EOF
	case read := <-c.reads:
		if read.err != nil {
			return 0, netip.AddrPort{}, read.err
		}
		copy(p, read.data)
		return len(read.data), read.from, nil
	}
}

func (c *scriptedPacketConn) WriteTo(b []byte, _ string) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.forceWriteN {
		return c.writeN, nil
	}
	return len(b), nil
}

func (c *scriptedPacketConn) Close() error {
	if c.closeCalls.Add(1) == 1 && c.closeCh != nil {
		close(c.closeCh)
	}
	return nil
}

func (c *scriptedPacketConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *scriptedPacketConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *scriptedPacketConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

func (c *scriptedTransportPacketConn) TransportDone() <-chan struct{} {
	return c.transportDone
}

func waitForCloseSignal(t *testing.T, ch <-chan struct{}, context string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for close signal: %s", context)
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, context string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for condition: %s", context)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func newTestEndpointDialer(conns ...netproxy.Conn) *componentdialer.Dialer {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return componentdialer.NewDialer(
		&scriptedDialer{conns: conns},
		&componentdialer.GlobalOption{
			Log:           logger,
			CheckInterval: time.Second,
		},
		componentdialer.InstanceOption{DisableCheck: true},
		&componentdialer.Property{},
	)
}

func newTestProxyEndpointDialer(protocol, address string, conns ...netproxy.Conn) *componentdialer.Dialer {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return componentdialer.NewDialer(
		&scriptedDialer{conns: conns},
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
	)
}

type errorDialer struct {
	err   error
	calls atomic.Int32
}

type blockingDialer struct {
	started chan struct{}
}

func (d *errorDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	d.calls.Add(1)
	return nil, d.err
}

func (d *blockingDialer) DialContext(ctx context.Context, _ string, _ string) (netproxy.Conn, error) {
	select {
	case <-d.started:
	default:
		close(d.started)
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func newTestEndpointErrorDialer(protocol, address string, err error) (*componentdialer.Dialer, *errorDialer) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	underlay := &errorDialer{err: err}
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

func newTestEndpointBlockingDialer(protocol, address string) (*componentdialer.Dialer, *blockingDialer) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	underlay := &blockingDialer{started: make(chan struct{})}
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

func newTestFixedOutboundGroup(dialers ...*componentdialer.Dialer) *ob.DialerGroup {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	annotations := make([]*componentdialer.Annotation, 0, len(dialers))
	for range dialers {
		annotations = append(annotations, &componentdialer.Annotation{})
	}
	return ob.NewDialerGroup(
		&componentdialer.GlobalOption{
			Log:           logger,
			CheckInterval: time.Second,
		},
		"fixed-test",
		dialers,
		annotations,
		ob.DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 0,
		},
		func(bool, *componentdialer.NetworkType, bool) {},
	)
}

func TestUdpEndpointRefreshTtlWithTime_UsesConfiguredLifetimeBeforeReply(t *testing.T) {
	now := time.Unix(123, 0)
	ue := &UdpEndpoint{
		NatTimeout: QuicNatTimeout,
	}

	ue.RefreshTtlWithTime(now.UnixNano())

	got := time.Duration(ue.expiresAtNano.Load() - now.UnixNano())
	want := QuicNatTimeout
	if got != want {
		t.Fatalf("expires delta = %v, want %v", got, want)
	}
}

func TestUdpEndpointPool_CreateEndpointLocked_UsesCallerContextCancellation(t *testing.T) {
	pool := NewUdpEndpointPool()
	t.Cleanup(pool.Close)

	testDialer, blocker := newTestEndpointBlockingDialer("socks5", "203.0.113.10:1080")
	t.Cleanup(func() {
		_ = testDialer.Close()
	})

	baseCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	createOption := &UdpEndpointOptions{
		Ctx: baseCtx,
		Handler: func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error {
			return nil
		},
		GetDialOption: func(ctx context.Context) (*DialOption, error) {
			return &DialOption{
				Dialer:  testDialer,
				Network: "udp",
				Target:  "198.51.100.1:53",
			}, nil
		},
		Log: logrus.New(),
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := pool.createEndpointLocked(UdpEndpointKey{Src: netip.MustParseAddrPort("127.0.0.1:30000")}, createOption)
		errCh <- err
	}()

	select {
	case <-blocker.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for blocking dialer to start")
	}

	cancel()

	select {
	case err := <-errCh:
		if !stderrors.Is(err, context.Canceled) {
			t.Fatalf("createEndpointLocked error = %v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for endpoint creation to honor caller cancellation")
	}
}

func TestUdpEndpointRefreshTtlWithTime_ProxyBackedUsesFullInitialLifetime(t *testing.T) {
	now := time.Unix(234, 0)
	ue := &UdpEndpoint{
		NatTimeout: QuicNatTimeout,
		Dialer:     newTestProxyEndpointDialer("hysteria2", "proxy.example:443"),
	}

	ue.RefreshTtlWithTime(now.UnixNano())

	if got := time.Duration(ue.expiresAtNano.Load() - now.UnixNano()); got != QuicNatTimeout {
		t.Fatalf("expires delta = %v, want %v", got, QuicNatTimeout)
	}
}

func TestUdpEndpointRefreshTtlWithTime_ExtendsDeadlineBeforeReply(t *testing.T) {
	now := time.Unix(456, 0)
	ue := &UdpEndpoint{
		NatTimeout: QuicNatTimeout,
	}

	ue.RefreshTtlWithTime(now.UnixNano())
	firstDeadline := ue.expiresAtNano.Load()
	ue.RefreshTtlWithTime(now.Add(5 * time.Second).UnixNano())

	if got := ue.expiresAtNano.Load(); got <= firstDeadline {
		t.Fatalf("expiresAt = %v, want greater than %v", got, firstDeadline)
	}
}

func TestAnyfromRefreshTtlWithTime_DoesNotShortenExtendedDeadline(t *testing.T) {
	now := time.Unix(500, 0)
	extendedDeadline := now.Add(DefaultNatTimeout).UnixNano()
	af := &Anyfrom{
		ttl: AnyfromTimeout,
	}
	af.expiresAtNano.Store(extendedDeadline)

	af.RefreshTtlWithTime(now.Add(3 * time.Second).UnixNano())

	if got := af.expiresAtNano.Load(); got != extendedDeadline {
		t.Fatalf("expiresAt = %v, want %v", got, extendedDeadline)
	}
}

func TestUdpEndpointRefreshTtlWithTime_ExtendsFullConeCachedResponseConnsToEndpointDeadline(t *testing.T) {
	now := time.Unix(520, 0)
	ue := &UdpEndpoint{
		NatTimeout: DefaultNatTimeout,
	}
	bindA := netip.MustParseAddrPort("127.0.0.1:20001")
	bindB := netip.MustParseAddrPort("127.0.0.1:20002")
	connA := &Anyfrom{ttl: AnyfromTimeout}
	connB := &Anyfrom{ttl: AnyfromTimeout}

	ue.StoreCachedResponseConn(bindA, connA)
	ue.StoreCachedResponseConn(bindB, connB)
	ue.RefreshTtlWithTime(now.UnixNano())

	wantDeadline := now.UnixNano() + int64(DefaultNatTimeout)
	if got := ue.expiresAtNano.Load(); got != wantDeadline {
		t.Fatalf("endpoint expiresAt = %v, want %v", got, wantDeadline)
	}
	if got := connA.expiresAtNano.Load(); got != wantDeadline {
		t.Fatalf("connA expiresAt = %v, want %v", got, wantDeadline)
	}
	if got := connB.expiresAtNano.Load(); got != wantDeadline {
		t.Fatalf("connB expiresAt = %v, want %v", got, wantDeadline)
	}
	if got := connA.pins.Load(); got != 1 {
		t.Fatalf("connA pins = %d, want 1", got)
	}
	if got := connB.pins.Load(); got != 1 {
		t.Fatalf("connB pins = %d, want 1", got)
	}
}

func TestUdpEndpointPromoteAfterReply_UsesFullLifetimeImmediately(t *testing.T) {
	now := time.Unix(789, 0)
	ue := &UdpEndpoint{
		NatTimeout: QuicNatTimeout,
	}

	ue.RefreshTtlWithTime(now.UnixNano())
	ue.markReplied(now.Add(50 * time.Millisecond).UnixNano())

	got := time.Duration(ue.expiresAtNano.Load() - ue.lastRefreshNano.Load())
	if got != QuicNatTimeout {
		t.Fatalf("expires delta = %v, want %v", got, QuicNatTimeout)
	}
}

func TestUdpEndpointClose_ReleasesCachedResponseConnPins(t *testing.T) {
	ue := &UdpEndpoint{
		poolKey: UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.10:40000")},
	}
	bindA := netip.MustParseAddrPort("127.0.0.1:21001")
	bindB := netip.MustParseAddrPort("127.0.0.1:21002")
	connA := &Anyfrom{ttl: AnyfromTimeout}
	connB := &Anyfrom{ttl: AnyfromTimeout}

	ue.StoreCachedResponseConn(bindA, connA)
	ue.StoreCachedResponseConn(bindB, connB)

	if got := connA.pins.Load(); got != 1 {
		t.Fatalf("connA pins before close = %d, want 1", got)
	}
	if got := connB.pins.Load(); got != 1 {
		t.Fatalf("connB pins before close = %d, want 1", got)
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}

	if got := connA.pins.Load(); got != 0 {
		t.Fatalf("connA pins after close = %d, want 0", got)
	}
	if got := connB.pins.Load(); got != 0 {
		t.Fatalf("connB pins after close = %d, want 0", got)
	}
	if got := ue.CachedResponseConn(bindA); got != nil {
		t.Fatalf("CachedResponseConn(bindA) after close = %p, want nil", got)
	}
	if got := ue.CachedResponseConn(bindB); got != nil {
		t.Fatalf("CachedResponseConn(bindB) after close = %p, want nil", got)
	}
}

func TestUdpEndpointClose_ReleasesTrackedUdpConnStateTuples(t *testing.T) {
	udpMap := newJanitorTestMap(t, "udp_conn_state_map")
	core := &controlPlaneCore{
		bpf: &bpfObjects{
			bpfMaps: bpfMaps{
				UdpConnStateMap: udpMap,
			},
		},
	}
	ue := &UdpEndpoint{
		poolKey: UdpEndpointKey{
			Src: netip.MustParseAddrPort("192.0.2.10:40000"),
		},
		udpConnStateOwner: core,
	}

	src := netip.MustParseAddrPort("192.0.2.10:40000")
	peers := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.1:27015"),
		netip.MustParseAddrPort("203.0.113.2:3478"),
	}

	for _, dst := range peers {
		ue.TrackUdpConnStateTuplePair(src, dst)

		for _, key := range []bpfTuplesKey{
			bpfTuplesKeyFromAddrPorts(src, dst, uint8(syscall.IPPROTO_UDP)),
			bpfTuplesKeyFromAddrPorts(dst, src, uint8(syscall.IPPROTO_UDP)),
		} {
			state := bpfUdpConnState{LastSeenNs: 1}
			if err := udpMap.Update(&key, &state, ebpf.UpdateAny); err != nil {
				t.Fatalf("update udp conn-state %v: %v", key, err)
			}
		}
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}

	for _, dst := range peers {
		for _, key := range []bpfTuplesKey{
			bpfTuplesKeyFromAddrPorts(src, dst, uint8(syscall.IPPROTO_UDP)),
			bpfTuplesKeyFromAddrPorts(dst, src, uint8(syscall.IPPROTO_UDP)),
		} {
			var state bpfUdpConnState
			if err := udpMap.Lookup(&key, &state); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("Lookup(%v) err = %v, want %v", key, err, ebpf.ErrKeyNotExist)
			}
		}
	}
}

func TestUdpEndpointAcceptsInitialReplyFrom_SymmetricRequiresExactPeer(t *testing.T) {
	ue := &UdpEndpoint{
		poolKey: UdpEndpointKey{
			Dst: netip.MustParseAddrPort("198.51.100.10:443"),
		},
	}
	ue.rememberPendingReplyPeer("198.51.100.10:443")

	if !ue.acceptsInitialReplyFrom(netip.MustParseAddrPort("198.51.100.10:443")) {
		t.Fatal("expected exact symmetric peer to be accepted")
	}
	if ue.acceptsInitialReplyFrom(netip.MustParseAddrPort("198.51.100.10:8443")) {
		t.Fatal("expected different symmetric peer port to be rejected")
	}
}

func TestUdpEndpointAcceptsInitialReplyFrom_FullConeAllowsSameIpFallback(t *testing.T) {
	ue := &UdpEndpoint{
		poolKey: UdpEndpointKey{},
	}
	ue.rememberPendingReplyPeer("203.0.113.10:3478")

	if !ue.acceptsInitialReplyFrom(netip.MustParseAddrPort("203.0.113.10:50000")) {
		t.Fatal("expected same-IP full-cone reply to be accepted")
	}
	if ue.acceptsInitialReplyFrom(netip.MustParseAddrPort("203.0.113.11:3478")) {
		t.Fatal("expected different-IP full-cone reply to be rejected")
	}
}

func TestUdpEndpointStart_DropsUnexpectedInitialReplyUntilPeerMatches(t *testing.T) {
	conn := &scriptedPacketConn{
		reads: make(chan scriptedPacketRead, 3),
	}
	handled := make(chan netip.AddrPort, 1)
	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: QuicNatTimeout,
		handler: func(_ *UdpEndpoint, _ []byte, from netip.AddrPort) error {
			handled <- from
			return nil
		},
	}
	ue.rememberPendingReplyPeer("203.0.113.10:3478")

	done := make(chan struct{})
	go func() {
		defer close(done)
		ue.start()
	}()

	conn.reads <- scriptedPacketRead{
		data: []byte("unexpected"),
		from: netip.MustParseAddrPort("198.51.100.1:1111"),
	}
	conn.reads <- scriptedPacketRead{
		data: []byte("expected"),
		from: netip.MustParseAddrPort("203.0.113.10:50000"),
	}
	conn.reads <- scriptedPacketRead{err: io.EOF}

	select {
	case from := <-handled:
		if from != netip.MustParseAddrPort("203.0.113.10:50000") {
			t.Fatalf("handler saw from = %v, want matched peer", from)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for matched initial reply to be handled")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for read loop to exit")
	}

	if !ue.hasReply.Load() {
		t.Fatal("expected endpoint to be promoted after matched initial reply")
	}
}

func TestUdpEndpointStart_NormalReadExitKeepsEndpointReusable(t *testing.T) {
	pool := NewUdpEndpointPool()
	key := UdpEndpointKey{Src: netip.MustParseAddrPort("127.0.0.1:15001")}
	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead, 1),
		closeCh: make(chan struct{}),
	}
	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: QuicNatTimeout,
		handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
		poolRef:    pool,
		poolKey:    key,
	}

	shard := pool.shardFor(key)
	shard.mu.Lock()
	shard.pool[key] = ue
	shard.mu.Unlock()
	pool.registerEndpoint(ue)
	pool.registerEndpoint(ue)

	done := make(chan struct{})
	go func() {
		defer close(done)
		ue.start()
	}()

	conn.reads <- scriptedPacketRead{err: io.EOF}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for read loop to exit after normal close")
	}

	if ue.IsDead() {
		t.Fatal("expected EOF read exit to keep endpoint reusable")
	}
	if got := conn.closeCalls.Load(); got != 0 {
		t.Fatalf("close calls = %d, want 0", got)
	}
	if got, ok := pool.Get(key); !ok || got != ue {
		t.Fatal("expected endpoint to remain in pool after normal read exit")
	}

	var createCalls atomic.Int32
	reused, isNew, err := pool.GetOrCreate(key, &UdpEndpointOptions{
		Handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
		NatTimeout: time.Second,
		GetDialOption: func(context.Context) (*DialOption, error) {
			createCalls.Add(1)
			return nil, io.ErrUnexpectedEOF
		},
	})
	if err != nil {
		t.Fatalf("GetOrCreate after normal read exit: %v", err)
	}
	if isNew {
		t.Fatal("expected pooled endpoint reuse after normal read exit")
	}
	if reused != ue {
		t.Fatal("expected GetOrCreate to return existing endpoint after normal read exit")
	}
	if got := createCalls.Load(); got != 0 {
		t.Fatalf("create calls = %d, want 0", got)
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
	waitForCloseSignal(t, conn.closeCh, "manual close after normal read exit should close the socket")
}

func TestUdpEndpointStart_ProxyBackedNormalReadExitRetiresEndpoint(t *testing.T) {
	pool := NewUdpEndpointPool()
	key := UdpEndpointKey{Src: netip.MustParseAddrPort("127.0.0.1:15002")}
	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead, 1),
		closeCh: make(chan struct{}),
	}
	ue := &UdpEndpoint{
		conn:                conn,
		NatTimeout:          QuicNatTimeout,
		Dialer:              newTestProxyEndpointDialer("hysteria2", "proxy.example:443"),
		handler:             func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
		poolRef:             pool,
		poolKey:             key,
		endpointNetworkType: componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4},
	}

	shard := pool.shardFor(key)
	shard.mu.Lock()
	shard.pool[key] = ue
	shard.mu.Unlock()
	pool.registerEndpoint(ue)

	done := make(chan struct{})
	go func() {
		defer close(done)
		ue.start()
	}()

	conn.reads <- scriptedPacketRead{err: io.EOF}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for proxy-backed read loop to exit after EOF")
	}

	if !ue.IsDead() {
		t.Fatal("expected proxy-backed EOF read exit to retire endpoint")
	}
	if got := conn.closeCalls.Load(); got != 1 {
		t.Fatalf("close calls = %d, want 1", got)
	}
	if _, ok := pool.Get(key); ok {
		t.Fatal("expected proxy-backed endpoint to be removed from pool after EOF")
	}
}

func TestUdpEndpointStart_TransportLifecycleRetiresEndpointBeforeReadError(t *testing.T) {
	pool := NewUdpEndpointPool()
	key := UdpEndpointKey{Src: netip.MustParseAddrPort("127.0.0.1:15021")}
	conn := &scriptedTransportPacketConn{
		scriptedPacketConn: &scriptedPacketConn{
			reads:   make(chan scriptedPacketRead),
			closeCh: make(chan struct{}),
		},
		transportDone: make(chan struct{}),
	}
	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: QuicNatTimeout,
		handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
		poolRef:    pool,
		poolKey:    key,
	}

	shard := pool.shardFor(key)
	shard.mu.Lock()
	shard.pool[key] = ue
	shard.mu.Unlock()
	pool.registerEndpoint(ue)

	done := make(chan struct{})
	go func() {
		defer close(done)
		ue.start()
	}()

	close(conn.transportDone)

	waitForCloseSignal(t, conn.closeCh, "transport lifecycle shutdown should close the endpoint")

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for read loop to exit after transport shutdown")
	}

	if !ue.IsDead() {
		t.Fatal("expected transport lifecycle shutdown to retire the endpoint")
	}
	if _, ok := pool.Get(key); ok {
		t.Fatal("expected retired endpoint to be removed from pool after transport shutdown")
	}
}

func TestUdpEndpointPool_TransportLifecycleSharesSingleBucketPerTransport(t *testing.T) {
	pool := NewUdpEndpointPool()
	sharedTransportDone := make(chan struct{})

	newEndpoint := func(src string) (*UdpEndpoint, *scriptedTransportPacketConn, chan struct{}) {
		conn := &scriptedTransportPacketConn{
			scriptedPacketConn: &scriptedPacketConn{
				reads:   make(chan scriptedPacketRead),
				closeCh: make(chan struct{}),
			},
			transportDone: sharedTransportDone,
		}
		key := UdpEndpointKey{Src: netip.MustParseAddrPort(src)}
		ue := &UdpEndpoint{
			conn:       conn,
			NatTimeout: QuicNatTimeout,
			handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
			poolRef:    pool,
			poolKey:    key,
		}
		shard := pool.shardFor(key)
		shard.mu.Lock()
		shard.pool[key] = ue
		shard.mu.Unlock()
		pool.registerEndpoint(ue)

		done := make(chan struct{})
		go func() {
			defer close(done)
			ue.start()
		}()
		return ue, conn, done
	}

	_, conn1, done1 := newEndpoint("127.0.0.1:16001")
	_, conn2, done2 := newEndpoint("127.0.0.1:16002")

	actual, ok := pool.transportIndex.Load((<-chan struct{})(sharedTransportDone))
	if !ok {
		t.Fatal("expected shared transport to be indexed once")
	}
	bucket := actual.(*udpEndpointTransportBucket)
	bucket.mu.RLock()
	if got := len(bucket.endpoints); got != 2 {
		bucket.mu.RUnlock()
		t.Fatalf("shared transport bucket size = %d, want 2", got)
	}
	bucket.mu.RUnlock()

	close(sharedTransportDone)

	waitForCloseSignal(t, conn1.closeCh, "shared transport shutdown should close first endpoint")
	waitForCloseSignal(t, conn2.closeCh, "shared transport shutdown should close second endpoint")

	select {
	case <-done1:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first read loop to exit after shared transport shutdown")
	}
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for second read loop to exit after shared transport shutdown")
	}

	if _, ok := pool.transportIndex.Load((<-chan struct{})(sharedTransportDone)); ok {
		t.Fatal("expected closed shared transport bucket to be removed from index")
	}
}

func TestUdpEndpointStart_HardReadErrorClosesConn(t *testing.T) {
	pool := NewUdpEndpointPool()
	key := UdpEndpointKey{Src: netip.MustParseAddrPort("127.0.0.1:15003")}
	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead, 1),
		closeCh: make(chan struct{}),
	}
	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: QuicNatTimeout,
		handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
		poolRef:    pool,
		poolKey:    key,
	}

	shard := pool.shardFor(key)
	shard.mu.Lock()
	shard.pool[key] = ue
	shard.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		ue.start()
	}()

	conn.reads <- scriptedPacketRead{err: io.ErrUnexpectedEOF}

	waitForCloseSignal(t, conn.closeCh, "hard read error should retire the endpoint")

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for read loop to exit after hard read error")
	}

	if !ue.IsDead() {
		t.Fatal("expected endpoint to be marked dead after hard read error")
	}
	if _, ok := pool.Get(key); ok {
		t.Fatal("expected endpoint to be removed from pool after hard read error")
	}
}

func TestUdpEndpointStart_HandlerErrorClosesConn(t *testing.T) {
	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead, 1),
		closeCh: make(chan struct{}),
	}
	wantErr := io.ErrUnexpectedEOF
	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: QuicNatTimeout,
		handler: func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error {
			return wantErr
		},
	}
	ue.hasReply.Store(true)

	done := make(chan struct{})
	go func() {
		defer close(done)
		ue.start()
	}()

	conn.reads <- scriptedPacketRead{
		data: []byte("payload"),
		from: netip.MustParseAddrPort("203.0.113.10:3478"),
	}

	waitForCloseSignal(t, conn.closeCh, "handler error should retire the endpoint")

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for read loop to exit after handler error")
	}

	if !ue.IsDead() {
		t.Fatal("expected endpoint to be marked dead after handler error")
	}
}

func TestUdpEndpointWriteTo_ErrorClosesConn(t *testing.T) {
	conn := &scriptedPacketConn{
		writeErr: io.ErrClosedPipe,
		closeCh:  make(chan struct{}),
	}
	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: QuicNatTimeout,
	}

	_, err := ue.WriteTo([]byte("payload"), "203.0.113.10:3478")
	if err == nil {
		t.Fatal("expected write error")
	}

	waitForCloseSignal(t, conn.closeCh, "write error should close the socket")

	if !ue.IsDead() {
		t.Fatal("expected endpoint to be marked dead after write error")
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
	if got := conn.closeCalls.Load(); got != 1 {
		t.Fatalf("close calls = %d, want 1", got)
	}
}

func TestUdpEndpointPoolInvalidateDialerNetworkType_ClosesOnlyMatchingEndpoints(t *testing.T) {
	pool := NewUdpEndpointPool()

	conn1 := &scriptedPacketConn{reads: make(chan scriptedPacketRead), closeCh: make(chan struct{})}
	conn2 := &scriptedPacketConn{reads: make(chan scriptedPacketRead), closeCh: make(chan struct{})}
	conn3 := &scriptedPacketConn{reads: make(chan scriptedPacketRead), closeCh: make(chan struct{})}
	conn4 := &scriptedPacketConn{reads: make(chan scriptedPacketRead), closeCh: make(chan struct{})}
	conn5 := &scriptedPacketConn{reads: make(chan scriptedPacketRead), closeCh: make(chan struct{})}

	d1 := newTestEndpointDialer(conn1, conn2, conn3)
	d2 := newTestEndpointDialer(conn4, conn5)

	key1 := UdpEndpointKey{
		Src: netip.MustParseAddrPort("127.0.0.1:10001"),
	}
	key2 := UdpEndpointKey{
		Src: netip.MustParseAddrPort("127.0.0.1:10002"),
	}
	key3 := UdpEndpointKey{
		Src: netip.MustParseAddrPort("127.0.0.1:10003"),
	}
	key4 := UdpEndpointKey{
		Src: netip.MustParseAddrPort("127.0.0.1:10004"),
	}
	key5 := UdpEndpointKey{
		Src: netip.MustParseAddrPort("[::1]:10005"),
	}

	makeEndpoint := func(target string, d *componentdialer.Dialer) *UdpEndpointOptions {
		return &UdpEndpointOptions{
			Handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
			NatTimeout: time.Second,
			GetDialOption: func(context.Context) (*DialOption, error) {
				ipVersion := consts.IpVersionStr_4
				if addr, err := netip.ParseAddrPort(target); err == nil {
					ipVersion = consts.IpVersionFromAddr(addr.Addr())
				}
				return &DialOption{
					Dialer:  d,
					Network: "udp",
					Target:  target,
					NetworkType: &componentdialer.NetworkType{
						L4Proto:   consts.L4ProtoStr_UDP,
						IpVersion: ipVersion,
						IsDns:     false,
					},
				}, nil
			},
		}
	}

	if _, _, err := pool.GetOrCreate(key1, makeEndpoint("198.51.100.1:443", d1)); err != nil {
		t.Fatalf("create endpoint 1: %v", err)
	}
	if _, _, err := pool.GetOrCreate(key2, makeEndpoint("[2001:db8::2]:443", d1)); err != nil {
		t.Fatalf("create endpoint 2: %v", err)
	}
	if _, _, err := pool.GetOrCreate(key3, makeEndpoint("[2001:db8::3]:443", d1)); err != nil {
		t.Fatalf("create endpoint 3: %v", err)
	}
	if _, _, err := pool.GetOrCreate(key4, makeEndpoint("198.51.100.4:443", d2)); err != nil {
		t.Fatalf("create endpoint 4: %v", err)
	}
	if _, _, err := pool.GetOrCreate(key5, makeEndpoint("[2001:db8::5]:443", d2)); err != nil {
		t.Fatalf("create endpoint 5: %v", err)
	}

	removed := pool.InvalidateDialerNetworkType(d1, &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStr_6,
		IsDns:     false,
	})
	if removed != 2 {
		t.Fatalf("removed = %d, want 2", removed)
	}

	waitForCloseSignal(t, conn2.closeCh, "first matching IPv6 endpoint should close")
	waitForCloseSignal(t, conn3.closeCh, "second matching IPv6 endpoint should close")

	if _, ok := pool.Get(key1); !ok {
		t.Fatal("expected same-dialer IPv4 endpoint to remain in pool")
	}
	if _, ok := pool.Get(key2); ok {
		t.Fatal("expected first matching IPv6 endpoint to be removed from pool")
	}
	if _, ok := pool.Get(key3); ok {
		t.Fatal("expected second matching IPv6 endpoint to be removed from pool")
	}
	if _, ok := pool.Get(key4); !ok {
		t.Fatal("expected unrelated dialer IPv4 endpoint to remain in pool")
	}
	if _, ok := pool.Get(key5); !ok {
		t.Fatal("expected unrelated dialer IPv6 endpoint to remain in pool")
	}
}

func TestUdpEndpointPoolInvalidateDialerNetworkType_DoesNotTouchFixedEndpoints(t *testing.T) {
	pool := NewUdpEndpointPool()

	connFixed := &scriptedPacketConn{reads: make(chan scriptedPacketRead), closeCh: make(chan struct{})}
	connNormal := &scriptedPacketConn{reads: make(chan scriptedPacketRead), closeCh: make(chan struct{})}
	d := newTestEndpointDialer(connFixed, connNormal)
	fixedOutbound := newTestFixedOutboundGroup(d)

	makeEndpoint := func(target string, outbound *ob.DialerGroup) *UdpEndpointOptions {
		return &UdpEndpointOptions{
			Handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
			NatTimeout: time.Second,
			GetDialOption: func(context.Context) (*DialOption, error) {
				return &DialOption{
					Dialer:   d,
					Outbound: outbound,
					Network:  "udp",
					Target:   target,
					NetworkType: &componentdialer.NetworkType{
						L4Proto:   consts.L4ProtoStr_UDP,
						IpVersion: consts.IpVersionStr_6,
						IsDns:     false,
					},
				}, nil
			},
		}
	}

	keyFixed := UdpEndpointKey{Src: netip.MustParseAddrPort("[::1]:11001")}
	keyNormal := UdpEndpointKey{Src: netip.MustParseAddrPort("[::1]:11002")}

	if _, _, err := pool.GetOrCreate(keyFixed, makeEndpoint("[2001:db8::10]:443", fixedOutbound)); err != nil {
		t.Fatalf("create fixed endpoint: %v", err)
	}
	if _, _, err := pool.GetOrCreate(keyNormal, makeEndpoint("[2001:db8::11]:443", nil)); err != nil {
		t.Fatalf("create normal endpoint: %v", err)
	}

	removed := pool.InvalidateDialerNetworkType(d, &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStr_6,
		IsDns:     false,
	})
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}

	waitForCloseSignal(t, connNormal.closeCh, "normal endpoint should close")

	if _, ok := pool.Get(keyNormal); ok {
		t.Fatal("expected normal endpoint to be removed from pool")
	}
	if _, ok := pool.Get(keyFixed); !ok {
		t.Fatal("expected fixed endpoint to remain available")
	}
	if got := connFixed.closeCalls.Load(); got != 0 {
		t.Fatalf("fixed endpoint close calls = %d, want 0", got)
	}
}

func TestUdpEndpointPoolInvalidateDialerNetworkType_PreservesEstablishedEndpointsPerNode(t *testing.T) {
	pool := NewUdpEndpointPool()

	connSticky := &scriptedPacketConn{reads: make(chan scriptedPacketRead), closeCh: make(chan struct{})}
	connProbing := &scriptedPacketConn{reads: make(chan scriptedPacketRead), closeCh: make(chan struct{})}
	connOtherNode := &scriptedPacketConn{reads: make(chan scriptedPacketRead), closeCh: make(chan struct{})}

	d1 := newTestEndpointDialer(connSticky, connProbing)
	d2 := newTestEndpointDialer(connOtherNode)
	outbound := newTestRandomOutboundGroup(d1, d2)

	makeEndpoint := func(d *componentdialer.Dialer, target string) *UdpEndpointOptions {
		return &UdpEndpointOptions{
			Handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
			NatTimeout: time.Second,
			GetDialOption: func(context.Context) (*DialOption, error) {
				return &DialOption{
					Dialer:   d,
					Outbound: outbound,
					Network:  "udp",
					Target:   target,
					NetworkType: &componentdialer.NetworkType{
						L4Proto:   consts.L4ProtoStr_UDP,
						IpVersion: consts.IpVersionStr_6,
						IsDns:     false,
					},
				}, nil
			},
		}
	}

	keySticky := UdpEndpointKey{Src: netip.MustParseAddrPort("[::1]:11501")}
	keyProbing := UdpEndpointKey{Src: netip.MustParseAddrPort("[::1]:11502")}
	keyOtherNode := UdpEndpointKey{Src: netip.MustParseAddrPort("[::1]:11503")}

	sticky, _, err := pool.GetOrCreate(keySticky, makeEndpoint(d1, "[2001:db8::10]:443"))
	if err != nil {
		t.Fatalf("create sticky endpoint: %v", err)
	}
	sticky.hasReply.Store(true)

	probing, _, err := pool.GetOrCreate(keyProbing, makeEndpoint(d1, "[2001:db8::11]:443"))
	if err != nil {
		t.Fatalf("create probing endpoint: %v", err)
	}
	otherNode, _, err := pool.GetOrCreate(keyOtherNode, makeEndpoint(d2, "[2001:db8::12]:443"))
	if err != nil {
		t.Fatalf("create other-node endpoint: %v", err)
	}
	otherNode.hasReply.Store(true)

	removed := pool.InvalidateDialerNetworkType(d1, &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStr_6,
		IsDns:     false,
	})
	if removed != 1 {
		t.Fatalf("removed = %d, want 1 probing endpoint from the failed node", removed)
	}

	waitForCloseSignal(t, connProbing.closeCh, "probing endpoint on failed node should close")

	if got, ok := pool.Get(keySticky); !ok || got != sticky {
		t.Fatal("expected established endpoint on failed node to remain reusable")
	}
	if _, ok := pool.Get(keyProbing); ok {
		t.Fatal("expected probing endpoint on failed node to be removed")
	}
	if got, ok := pool.Get(keyOtherNode); !ok || got != otherNode {
		t.Fatal("expected endpoint on other node in the same outbound group to remain available")
	}
	if got := connSticky.closeCalls.Load(); got != 0 {
		t.Fatalf("sticky endpoint close calls = %d, want 0", got)
	}
	if got := connOtherNode.closeCalls.Load(); got != 0 {
		t.Fatalf("other-node endpoint close calls = %d, want 0", got)
	}

	if err := sticky.Close(); err != nil {
		t.Fatalf("close sticky endpoint: %v", err)
	}
	if err := probing.Close(); err != nil {
		t.Fatalf("close probing endpoint: %v", err)
	}
	if err := otherNode.Close(); err != nil {
		t.Fatalf("close other-node endpoint: %v", err)
	}
}

func TestUdpEndpointPoolInvalidateDialerNetworkType_PreservesForwardedUnrepliedEndpoints(t *testing.T) {
	pool := NewUdpEndpointPool()

	connForwarded := &scriptedPacketConn{reads: make(chan scriptedPacketRead), closeCh: make(chan struct{})}
	connNeverUsed := &scriptedPacketConn{reads: make(chan scriptedPacketRead), closeCh: make(chan struct{})}

	d := newTestEndpointDialer(connForwarded, connNeverUsed)
	outbound := newTestRandomOutboundGroup(d)

	makeEndpoint := func(target string) *UdpEndpointOptions {
		return &UdpEndpointOptions{
			Handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
			NatTimeout: time.Second,
			GetDialOption: func(context.Context) (*DialOption, error) {
				return &DialOption{
					Dialer:   d,
					Outbound: outbound,
					Network:  "udp",
					Target:   target,
					NetworkType: &componentdialer.NetworkType{
						L4Proto:   consts.L4ProtoStr_UDP,
						IpVersion: consts.IpVersionStr_6,
						IsDns:     false,
					},
				}, nil
			},
		}
	}

	keyForwarded := UdpEndpointKey{Src: netip.MustParseAddrPort("[::1]:11601")}
	keyNeverUsed := UdpEndpointKey{Src: netip.MustParseAddrPort("[::1]:11602")}

	forwarded, _, err := pool.GetOrCreate(keyForwarded, makeEndpoint("[2001:db8::20]:443"))
	if err != nil {
		t.Fatalf("create forwarded endpoint: %v", err)
	}
	forwarded.hasSent.Store(true)

	neverUsed, _, err := pool.GetOrCreate(keyNeverUsed, makeEndpoint("[2001:db8::21]:443"))
	if err != nil {
		t.Fatalf("create never-used endpoint: %v", err)
	}

	removed := pool.InvalidateDialerNetworkType(d, &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStr_6,
		IsDns:     false,
	})
	if removed != 1 {
		t.Fatalf("removed = %d, want 1 never-used endpoint", removed)
	}

	waitForCloseSignal(t, connNeverUsed.closeCh, "never-used endpoint should close after invalidation")

	if got, ok := pool.Get(keyForwarded); !ok || got != forwarded {
		t.Fatal("expected forwarded endpoint to remain reusable after invalidation")
	}
	if got := connForwarded.closeCalls.Load(); got != 0 {
		t.Fatalf("forwarded endpoint close calls = %d, want 0", got)
	}
	if got, ok := pool.Get(keyNeverUsed); ok || got == neverUsed {
		t.Fatal("expected never-used endpoint to be removed after invalidation")
	}
}

func TestUdpEndpointPoolUnregisterKeepsDialerBucketForReuse(t *testing.T) {
	pool := NewUdpEndpointPool()

	conn1 := &scriptedPacketConn{reads: make(chan scriptedPacketRead), closeCh: make(chan struct{})}
	conn2 := &scriptedPacketConn{reads: make(chan scriptedPacketRead), closeCh: make(chan struct{})}
	d := newTestEndpointDialer(conn1, conn2)

	makeEndpoint := func(target string) *UdpEndpointOptions {
		return &UdpEndpointOptions{
			Handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
			NatTimeout: time.Second,
			GetDialOption: func(context.Context) (*DialOption, error) {
				return &DialOption{
					Dialer:  d,
					Network: "udp",
					Target:  target,
					NetworkType: &componentdialer.NetworkType{
						L4Proto:   consts.L4ProtoStr_UDP,
						IpVersion: consts.IpVersionStr_6,
						IsDns:     false,
					},
				}, nil
			},
		}
	}

	key1 := UdpEndpointKey{Src: netip.MustParseAddrPort("[::1]:12001")}
	ue1, _, err := pool.GetOrCreate(key1, makeEndpoint("[2001:db8::20]:443"))
	if err != nil {
		t.Fatalf("create first endpoint: %v", err)
	}

	indexKey, ok := pool.endpointDialerNetworkKey(ue1)
	if !ok {
		t.Fatal("expected endpoint to have dialer network key")
	}
	actual, ok := pool.dialerIndex.Load(indexKey)
	if !ok {
		t.Fatal("expected dialer bucket to exist after registration")
	}
	bucket := actual.(*udpEndpointDialerBucket)

	if err := ue1.Close(); err != nil {
		t.Fatalf("close first endpoint: %v", err)
	}
	waitForCloseSignal(t, conn1.closeCh, "first endpoint should close")

	actual, ok = pool.dialerIndex.Load(indexKey)
	if !ok {
		t.Fatal("expected empty dialer bucket to remain after unregister")
	}
	if actual != bucket {
		t.Fatal("expected bucket instance to be retained for reuse")
	}
	bucket.mu.RLock()
	if len(bucket.endpoints) != 0 {
		bucket.mu.RUnlock()
		t.Fatalf("bucket endpoint count = %d, want 0", len(bucket.endpoints))
	}
	bucket.mu.RUnlock()

	key2 := UdpEndpointKey{Src: netip.MustParseAddrPort("[::1]:12002")}
	ue2, _, err := pool.GetOrCreate(key2, makeEndpoint("[2001:db8::21]:443"))
	if err != nil {
		t.Fatalf("create second endpoint: %v", err)
	}
	if ue2 == nil {
		t.Fatal("expected second endpoint to be created")
	}

	actual, ok = pool.dialerIndex.Load(indexKey)
	if !ok {
		t.Fatal("expected dialer bucket to still exist after reuse")
	}
	if actual != bucket {
		t.Fatal("expected registration to reuse the retained bucket")
	}
	bucket.mu.RLock()
	if len(bucket.endpoints) != 1 {
		bucket.mu.RUnlock()
		t.Fatalf("bucket endpoint count = %d, want 1", len(bucket.endpoints))
	}
	bucket.mu.RUnlock()
}

func TestUdpEndpointPoolGetOrCreate_NoAliveDialerDoesNotNegativeCachePerFlow(t *testing.T) {
	pool := NewUdpEndpointPool()
	key := UdpEndpointKey{Src: netip.MustParseAddrPort("[::1]:13001")}
	var calls atomic.Int32

	createOption := &UdpEndpointOptions{
		Handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
		NatTimeout: time.Second,
		GetDialOption: func(context.Context) (*DialOption, error) {
			calls.Add(1)
			return nil, ob.ErrNoAliveDialer
		},
	}

	if _, _, err := pool.GetOrCreate(key, createOption); err == nil || err != ob.ErrNoAliveDialer {
		t.Fatalf("first GetOrCreate err = %v, want %v", err, ob.ErrNoAliveDialer)
	}

	shard := pool.shardFor(key)
	shard.mu.RLock()
	_, ok := shard.pool[key]
	shard.mu.RUnlock()
	if ok {
		t.Fatal("expected no failed entry to be stored for no-alive admission rejection")
	}

	if _, _, err := pool.GetOrCreate(key, createOption); err == nil || err != ob.ErrNoAliveDialer {
		t.Fatalf("second GetOrCreate err = %v, want %v", err, ob.ErrNoAliveDialer)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("GetDialOption calls = %d, want 2", got)
	}
}

func TestUdpEndpointPoolGetOrCreate_GenericFailureStillNegativeCaches(t *testing.T) {
	pool := NewUdpEndpointPool()
	key := UdpEndpointKey{Src: netip.MustParseAddrPort("[::1]:13002")}
	var calls atomic.Int32

	createOption := &UdpEndpointOptions{
		Handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
		NatTimeout: time.Second,
		GetDialOption: func(context.Context) (*DialOption, error) {
			calls.Add(1)
			return nil, io.EOF
		},
	}

	if _, _, err := pool.GetOrCreate(key, createOption); err == nil || err != io.EOF {
		t.Fatalf("first GetOrCreate err = %v, want %v", err, io.EOF)
	}

	shard := pool.shardFor(key)
	shard.mu.RLock()
	failed, ok := shard.pool[key]
	shard.mu.RUnlock()
	if !ok || failed == nil || !failed.failed.Load() {
		t.Fatal("expected generic creation failure to store a failed entry")
	}

	if _, _, err := pool.GetOrCreate(key, createOption); err == nil || err != ErrEndpointFailed {
		t.Fatalf("second GetOrCreate err = %v, want %v", err, ErrEndpointFailed)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("GetDialOption calls = %d, want 1", got)
	}
}

func TestUdpEndpointWriteTo_ShortWriteClosesConn(t *testing.T) {
	conn := &scriptedPacketConn{
		writeN:      3,
		forceWriteN: true,
		closeCh:     make(chan struct{}),
	}
	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: QuicNatTimeout,
	}

	_, err := ue.WriteTo([]byte("payload"), "203.0.113.10:3478")
	if err == nil {
		t.Fatal("expected short write error")
	}

	waitForCloseSignal(t, conn.closeCh, "short write should close the socket")

	if !ue.IsDead() {
		t.Fatal("expected endpoint to be marked dead after short write")
	}
}

func TestUdpEndpointUpdateNatTimeout_ExtendsDeadlineBeforeReply(t *testing.T) {
	ue := &UdpEndpoint{
		NatTimeout: DefaultNatTimeout,
	}

	ue.RefreshTtlWithTime(time.Now().UnixNano())
	firstDeadline := ue.expiresAtNano.Load()
	ue.UpdateNatTimeout(QuicNatTimeout)

	if got := ue.expiresAtNano.Load(); got <= firstDeadline {
		t.Fatalf("expiresAt = %v, want greater than %v", got, firstDeadline)
	}
}

func TestUdpEndpointRefreshTtlWithTime_DoesNotStretchShortTimeout(t *testing.T) {
	now := time.Unix(1200, 0)
	timeout := 3 * time.Second
	ue := &UdpEndpoint{
		NatTimeout: timeout,
	}

	ue.RefreshTtlWithTime(now.UnixNano())

	got := time.Duration(ue.expiresAtNano.Load() - now.UnixNano())
	if got != timeout {
		t.Fatalf("expires delta = %v, want %v", got, timeout)
	}
}

func TestUdpEndpointRefreshTtlWithTime_ProxyBackedEndpointUsesSlidingLifetime(t *testing.T) {
	now := time.Unix(1300, 0)
	ue := &UdpEndpoint{
		NatTimeout: QuicNatTimeout,
		Dialer:     newTestProxyEndpointDialer("hysteria2", "proxy.example:443"),
	}

	ue.RefreshTtlWithTime(now.UnixNano())
	if got := time.Duration(ue.expiresAtNano.Load() - now.UnixNano()); got != QuicNatTimeout {
		t.Fatalf("initial expires delta = %v, want %v", got, QuicNatTimeout)
	}

	next := now.Add(5 * time.Second)
	ue.RefreshTtlWithTime(next.UnixNano())

	if got := ue.expiresAtNano.Load(); got != next.UnixNano()+int64(QuicNatTimeout) {
		t.Fatalf("expiresAt = %v, want %v", got, next.UnixNano()+int64(QuicNatTimeout))
	}
}

func TestUdpEndpointStart_ProxyBackedEndpointAcceptsFirstReplyWithoutPeerMatch(t *testing.T) {
	conn := &scriptedPacketConn{
		reads: make(chan scriptedPacketRead, 2),
	}
	handled := make(chan netip.AddrPort, 1)
	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: QuicNatTimeout,
		Dialer:     newTestProxyEndpointDialer("hysteria2", "proxy.example:443"),
		handler: func(_ *UdpEndpoint, _ []byte, from netip.AddrPort) error {
			handled <- from
			return nil
		},
	}
	ue.rememberPendingReplyPeer("203.0.113.10:3478")

	done := make(chan struct{})
	go func() {
		defer close(done)
		ue.start()
	}()

	wantFrom := netip.MustParseAddrPort("198.51.100.1:1111")
	conn.reads <- scriptedPacketRead{
		data: []byte("reply"),
		from: wantFrom,
	}
	conn.reads <- scriptedPacketRead{err: io.EOF}

	select {
	case from := <-handled:
		if from != wantFrom {
			t.Fatalf("handler saw from = %v, want %v", from, wantFrom)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for proxy-backed reply to be handled")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for read loop to exit")
	}

	if !ue.hasReply.Load() {
		t.Fatal("expected proxy-backed endpoint to promote after first reply")
	}
}

func TestEffectiveUdpEndpointNatTimeout_LongLivedProtocolsUseQuicFloor(t *testing.T) {
	d := newTestProxyEndpointDialer("hysteria2", "proxy.example:443")

	got := effectiveUdpEndpointNatTimeout(d, DefaultNatTimeout)
	if got != QuicNatTimeout {
		t.Fatalf("effective timeout = %v, want %v", got, QuicNatTimeout)
	}
}

func TestEffectiveUdpEndpointNatTimeout_ShadowsocksKeepsRequestedTimeout(t *testing.T) {
	d := newTestProxyEndpointDialer("shadowsocks", "proxy.example:443")

	got := effectiveUdpEndpointNatTimeout(d, DefaultNatTimeout)
	if got != DefaultNatTimeout {
		t.Fatalf("effective timeout = %v, want %v", got, DefaultNatTimeout)
	}
}

func TestUdpEndpointPoolGetOrCreate_LocalBindExhaustionDoesNotNegativeCachePerFlow(t *testing.T) {
	pool := NewUdpEndpointPool()
	key := UdpEndpointKey{Src: netip.MustParseAddrPort("[::1]:13003")}
	d, underlay := newTestEndpointErrorDialer(
		"shadowsocks",
		"proxy.example:443",
		&net.OpError{Op: "listen", Net: "udp", Err: syscall.EADDRINUSE},
	)

	createOption := &UdpEndpointOptions{
		Handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
		NatTimeout: time.Second,
		GetDialOption: func(context.Context) (*DialOption, error) {
			return &DialOption{
				Dialer:  d,
				Network: "udp",
				Target:  "[2001:db8::20]:443",
				NetworkType: &componentdialer.NetworkType{
					L4Proto:   consts.L4ProtoStr_UDP,
					IpVersion: consts.IpVersionStr_6,
					IsDns:     false,
				},
			}, nil
		},
	}

	if _, _, err := pool.GetOrCreate(key, createOption); err == nil || !stderrors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("first GetOrCreate err = %v, want wrapped EADDRINUSE", err)
	}

	shard := pool.shardFor(key)
	shard.mu.RLock()
	_, ok := shard.pool[key]
	shard.mu.RUnlock()
	if ok {
		t.Fatal("expected no failed entry to be stored for local bind exhaustion")
	}

	if _, _, err := pool.GetOrCreate(key, createOption); err == nil || !stderrors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("second GetOrCreate err = %v, want wrapped EADDRINUSE", err)
	}
	if got := underlay.calls.Load(); got != 2 {
		t.Fatalf("DialContext calls = %d, want 2", got)
	}
}

func TestProxyBackedUdpNatTimeout_FloorsShortTimeouts(t *testing.T) {
	if got := proxyBackedUdpNatTimeout(DefaultNatTimeout); got != QuicNatTimeout {
		t.Fatalf("proxyBackedUdpNatTimeout(DefaultNatTimeout) = %v, want %v", got, QuicNatTimeout)
	}
	if got := proxyBackedUdpNatTimeout(QuicNatTimeout); got != QuicNatTimeout {
		t.Fatalf("proxyBackedUdpNatTimeout(QuicNatTimeout) = %v, want %v", got, QuicNatTimeout)
	}
}

func TestUdpEndpointPoolGetOrCreate_ProxyBackedEndpointUsesLongerNatTimeout(t *testing.T) {
	pool := NewUdpEndpointPool()
	key := UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.10:40000")}
	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d := newTestProxyEndpointDialer("hysteria2", "proxy.example:443", conn)

	createOption := &UdpEndpointOptions{
		Handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
		NatTimeout: DefaultNatTimeout,
		GetDialOption: func(context.Context) (*DialOption, error) {
			return &DialOption{
				Dialer:  d,
				Network: "udp",
				Target:  "198.51.100.20:23002",
			}, nil
		},
	}

	ue, isNew, err := pool.GetOrCreate(key, createOption)
	if err != nil {
		t.Fatalf("first GetOrCreate error: %v", err)
	}
	if !isNew {
		t.Fatal("expected first GetOrCreate to create a new endpoint")
	}
	if got := ue.NatTimeout; got != QuicNatTimeout {
		t.Fatalf("NatTimeout = %v, want %v", got, QuicNatTimeout)
	}

	now := time.Now().UnixNano()
	if got := time.Duration(ue.expiresAtNano.Load() - now); got < QuicNatTimeout-time.Second {
		t.Fatalf("initial expires delta = %v, want close to %v", got, QuicNatTimeout)
	}

	reused, isNew, err := pool.GetOrCreate(key, createOption)
	if err != nil {
		t.Fatalf("second GetOrCreate error: %v", err)
	}
	if isNew {
		t.Fatal("expected second GetOrCreate to reuse endpoint")
	}
	if reused != ue {
		t.Fatal("expected second GetOrCreate to return the same endpoint")
	}
	if got := reused.NatTimeout; got != QuicNatTimeout {
		t.Fatalf("reused NatTimeout = %v, want %v", got, QuicNatTimeout)
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestUdpEndpointPoolGetOrCreate_FullConeEndpointPrewarmsCachedResponseConn(t *testing.T) {
	oldAnyfromPool := DefaultAnyfromPool
	DefaultAnyfromPool = newTestAnyfromPoolWithoutJanitor()
	defer func() {
		DefaultAnyfromPool.Reset()
		DefaultAnyfromPool = oldAnyfromPool
	}()

	pool := NewUdpEndpointPool()
	defer pool.Reset()

	key := UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.10:40000")}
	target := "198.51.100.20:23002"
	targetAddr := netip.MustParseAddrPort(target)
	bindAddr, _ := normalizeSendPktAddrFamily(targetAddr, key.Src)

	af := &Anyfrom{ttl: AnyfromTimeout}
	af.RefreshTtl()
	shard := DefaultAnyfromPool.shardFor(bindAddr)
	shard.mu.Lock()
	shard.pool[bindAddr] = af
	shard.mu.Unlock()

	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d := newTestProxyEndpointDialer("hysteria2", "proxy.example:443", conn)

	ue, isNew, err := pool.GetOrCreate(key, &UdpEndpointOptions{
		Handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
		NatTimeout: DefaultNatTimeout,
		GetDialOption: func(context.Context) (*DialOption, error) {
			return &DialOption{
				Dialer:  d,
				Network: "udp",
				Target:  target,
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("GetOrCreate() error = %v", err)
	}
	if !isNew {
		t.Fatal("expected GetOrCreate to create a new endpoint")
	}
	if got := ue.CachedResponseConn(bindAddr); got != af {
		t.Fatalf("CachedResponseConn(%v) = %p, want %p", bindAddr, got, af)
	}
	if got := af.pins.Load(); got != 1 {
		t.Fatalf("pins = %d, want 1", got)
	}
	if got, want := af.expiresAtNano.Load(), ue.expiresAtNano.Load(); got != want {
		t.Fatalf("anyfrom expiresAt = %v, want %v", got, want)
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
	if got := af.pins.Load(); got != 0 {
		t.Fatalf("pins after close = %d, want 0", got)
	}
}

func TestUdpEndpointPoolGetOrCreate_NoReplyTimeoutReleasesPrewarmedAnyfrom(t *testing.T) {
	oldAnyfromPool := DefaultAnyfromPool
	DefaultAnyfromPool = NewAnyfromPool()
	defer func() {
		DefaultAnyfromPool.Close()
		DefaultAnyfromPool = oldAnyfromPool
	}()

	pool := NewUdpEndpointPool()
	defer pool.Close()

	key := UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.10:40000")}
	target := "198.51.100.20:23002"
	targetAddr := netip.MustParseAddrPort(target)
	bindAddr, _ := normalizeSendPktAddrFamily(targetAddr, key.Src)

	af := &Anyfrom{ttl: 50 * time.Millisecond}
	af.RefreshTtl()
	shard := DefaultAnyfromPool.shardFor(bindAddr)
	shard.mu.Lock()
	shard.pool[bindAddr] = af
	shard.mu.Unlock()

	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d := newTestProxyEndpointDialer("shadowsocks", "proxy.example:443", conn)

	ue, isNew, err := pool.GetOrCreate(key, &UdpEndpointOptions{
		Handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
		NatTimeout: 50 * time.Millisecond,
		GetDialOption: func(context.Context) (*DialOption, error) {
			return &DialOption{
				Dialer:  d,
				Network: "udp",
				Target:  target,
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("GetOrCreate() error = %v", err)
	}
	if !isNew {
		t.Fatal("expected GetOrCreate to create a new endpoint")
	}
	if got := ue.CachedResponseConn(bindAddr); got != af {
		t.Fatalf("CachedResponseConn(%v) = %p, want %p", bindAddr, got, af)
	}
	if got := af.pins.Load(); got != 1 {
		t.Fatalf("pins after prewarm = %d, want 1", got)
	}

	waitForCloseSignal(t, conn.closeCh, "idle no-reply endpoint should expire and close")
	waitForCondition(t, 2*time.Second, "expired endpoint removed from pool", func() bool {
		_, ok := pool.Get(key)
		return !ok
	})
	waitForCondition(t, 2*time.Second, "prewarmed anyfrom pin released after endpoint timeout", func() bool {
		return af.pins.Load() == 0
	})
	waitForCondition(t, 2*time.Second, "anyfrom janitor reclaims released prewarm socket", func() bool {
		return countPooledAnyfromConns(DefaultAnyfromPool) == 0
	})
}
