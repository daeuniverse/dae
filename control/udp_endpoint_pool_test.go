/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"context"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
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

func waitForCloseSignal(t *testing.T, ch <-chan struct{}, context string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for close signal: %s", context)
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

func TestUdpEndpointRefreshTtlWithTime_BoundsInitialLifetimeByDialTimeout(t *testing.T) {
	now := time.Unix(123, 0)
	ue := &UdpEndpoint{
		NatTimeout: QuicNatTimeout,
	}

	ue.RefreshTtlWithTime(now.UnixNano())

	got := time.Duration(ue.expiresAtNano.Load() - now.UnixNano())
	want := 2 * consts.DefaultDialTimeout
	if got != want {
		t.Fatalf("expires delta = %v, want %v", got, want)
	}
}

func TestUdpEndpointRefreshTtlWithTime_DoesNotExtendUnrepliedDeadline(t *testing.T) {
	now := time.Unix(456, 0)
	ue := &UdpEndpoint{
		NatTimeout: QuicNatTimeout,
	}

	ue.RefreshTtlWithTime(now.UnixNano())
	firstDeadline := ue.expiresAtNano.Load()
	ue.RefreshTtlWithTime(now.Add(5 * time.Second).UnixNano())

	if got := ue.expiresAtNano.Load(); got != firstDeadline {
		t.Fatalf("expiresAt = %v, want %v", got, firstDeadline)
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

func TestUdpEndpointUpdateNatTimeout_DoesNotExtendUnrepliedDeadline(t *testing.T) {
	now := time.Unix(1000, 0)
	ue := &UdpEndpoint{
		NatTimeout: DefaultNatTimeout,
	}

	ue.RefreshTtlWithTime(now.UnixNano())
	firstDeadline := ue.expiresAtNano.Load()
	ue.UpdateNatTimeout(QuicNatTimeout)

	if got := ue.expiresAtNano.Load(); got != firstDeadline {
		t.Fatalf("expiresAt = %v, want %v", got, firstDeadline)
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
