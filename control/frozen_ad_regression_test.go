/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// Frozen A–D regressions. These pin the closed-loop patches without touching
// outbound/quic-go or adding hot-path cost.

func TestDoHForwardDNSObservesRequestContext(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var sawCancel atomic.Bool
	d := &DoH{
		Upstream: dns.Upstream{
			Scheme:   dns.UpstreamScheme_HTTPS,
			Hostname: "dns.example",
			Port:     443,
			Path:     "/dns-query",
		},
		dialArgument: dialArgument{bestTarget: netip.MustParseAddrPort("1.1.1.1:443")},
	}
	d.clientFactory = func() *http.Client { return &http.Client{} }
	d.sendFunc = func(ctx context.Context, _ *http.Client, _ string, _ *dns.Upstream, _ []byte) (*dnsmessage.Msg, error) {
		close(started)
		select {
		case <-ctx.Done():
			sawCancel.Store(true)
			return nil, ctx.Err()
		case <-release:
			return &dnsmessage.Msg{}, nil
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := d.ForwardDNS(ctx, []byte{0, 0, 1, 0})
		errCh <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("sendFunc did not observe the request")
	}
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ForwardDNS error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ForwardDNS did not return after ctx cancel")
	}
	if !sawCancel.Load() {
		t.Fatal("sendFunc did not observe ctx cancellation")
	}
	close(release)
}

func TestDoHGetClientHasNoClientTimeout(t *testing.T) {
	d := &DoH{
		Upstream:     dns.Upstream{Hostname: "dns.example"},
		dialArgument: dialArgument{bestTarget: netip.MustParseAddrPort("1.1.1.1:443")},
	}
	client := d.getClient()
	if client.Timeout != 0 {
		t.Fatalf("http.Client.Timeout = %v, want 0 (request ctx is the deadline)", client.Timeout)
	}
}

func TestBackgroundRefreshFailureKeepsStaleAndClearsRefreshing(t *testing.T) {
	ctrl := newTestDnsController()
	setTestDnsControllerRuntime(ctrl, func(rt *dnsControllerRuntimeState) {
		rt.bestDialerChooser = func(context.Context, DnsRequestSnapshot, *dns.Upstream) (*dialArgument, error) {
			return nil, errors.New("chooser stub: force refresh failure")
		}
	})

	cacheKey := "stale.example.com.1"
	stale := &DnsCache{
		Deadline:         time.Now().Add(-time.Minute),
		OriginalDeadline: time.Now().Add(-time.Minute),
	}
	stale.refreshing.Store(true)
	// Publish through the controller's store so the base-key index stays in sync.
	ctrl.storeDnsCache(cacheKey, stale)

	q := new(dnsmessage.Msg)
	q.SetQuestion("stale.example.com.", dnsmessage.TypeA)
	ctrl.backgroundRefresh(cacheKey, q, &udpRequest{realDst: netip.MustParseAddrPort("1.1.1.1:53")}, 0, &dns.Upstream{
		Scheme:   dns.UpstreamScheme_UDP,
		Hostname: "1.1.1.1",
		Port:     53,
	})

	val, ok := ctrl.dnsCache.Load(cacheKey)
	if !ok {
		t.Fatal("stale cache entry was evicted on refresh failure")
	}
	got, ok := val.(*DnsCache)
	if !ok || got != stale {
		t.Fatal("stale cache entry was replaced on refresh failure")
	}
	if got.IsRefreshing() {
		t.Fatal("refreshing flag still set after failed backgroundRefresh")
	}
}

func TestCloseWriteRelayConnUnwrapsBufioConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, accErr := ln.Accept()
		if accErr != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	server := <-accepted
	if server == nil {
		t.Fatal("Accept failed")
	}
	defer func() { _ = server.Close() }()

	tcpClient, ok := client.(*net.TCPConn)
	if !ok {
		t.Fatalf("client type %T, want *net.TCPConn", client)
	}
	wrapped := &bufioConn{Conn: tcpClient, reader: bufio.NewReader(tcpClient)}
	tcp, ok := unwrapRelayTCPConn(wrapped)
	if !ok || tcp != tcpClient {
		t.Fatalf("unwrapRelayTCPConn(%T) = (%v, %v), want underlying *net.TCPConn", wrapped, tcp, ok)
	}
	prefixed := &prefixedConn{Conn: wrapped}
	tcp, ok = unwrapRelayTCPConn(prefixed)
	if !ok || tcp != tcpClient {
		t.Fatalf("unwrapRelayTCPConn(prefixedConn) = (%v, %v), want underlying *net.TCPConn", tcp, ok)
	}
	closeWriteRelayConn(wrapped)

	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	n, readErr := server.Read(buf)
	if n != 0 || !errors.Is(readErr, io.EOF) {
		t.Fatalf("peer Read after CloseWrite = (%d, %v), want (0, EOF)", n, readErr)
	}
}

func TestUdpEndpointPoolRemoveUnlocksBeforeClose(t *testing.T) {
	p := NewUdpEndpointPool()
	t.Cleanup(p.Close)

	key := UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.1:40000")}
	ue := &UdpEndpoint{
		poolKey:        key,
		replyQueueCh:   make(chan *udpEndpointReply),
		replyQueueDone: make(chan struct{}),
	}
	shard := p.shardFor(key)
	shard.mu.Lock()
	shard.pool[key] = ue
	shard.mu.Unlock()

	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- p.Remove(key, ue)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("Remove did not start")
	}
	time.Sleep(20 * time.Millisecond)

	lockDone := make(chan struct{})
	go func() {
		defer close(lockDone)
		shard.mu.Lock()
		_ = shard.pool
		shard.mu.Unlock()
	}()
	select {
	case <-lockDone:
	case <-time.After(time.Second):
		close(ue.replyQueueDone)
		t.Fatal("shard.mu still held while Remove waited on Close")
	}

	close(ue.replyQueueDone)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Remove: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Remove did not return after replyQueueDone closed")
	}
}

func TestAbortTakesPendingEgressOnce(t *testing.T) {
	c := newOwnershipTestPlane()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	lease, ok := c.acquireIncomingConnectionLease(client)
	if !ok {
		t.Fatal("acquire rejected")
	}

	pending := &closeCountConn{}
	lease.storePendingEgress(pending)
	conns, flows, errs := c.takeIncomingConnectionsForAbort()
	if len(errs) != 0 {
		t.Fatalf("abort snapshot errors: %v", errs)
	}
	if len(conns) != 1 || conns[0] != client {
		t.Fatalf("abort connections = %v, want incoming conn", conns)
	}
	if len(flows) != 1 || flows[0] != pending {
		t.Fatalf("abort flows = %v, want pending egress", flows)
	}
	if second := lease.takePendingEgress(); second != nil {
		t.Fatal("pending egress was not cleared by abort snapshot")
	}
	lease.release()
	if pending.closeCount.Load() != 0 {
		t.Fatal("abort snapshot closed pending egress; AbortConnections owns Close")
	}
	_ = pending.Close()
	if pending.closeCount.Load() != 1 {
		t.Fatalf("pending close count = %d, want 1", pending.closeCount.Load())
	}
}

func TestReleaseClosesLeftoverPendingEgress(t *testing.T) {
	c := newOwnershipTestPlane()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	lease, ok := c.acquireIncomingConnectionLease(client)
	if !ok {
		t.Fatal("acquire rejected")
	}
	pending := &closeCountConn{}
	lease.storePendingEgress(pending)
	lease.release()
	if pending.closeCount.Load() != 1 {
		t.Fatalf("release close count = %d, want 1", pending.closeCount.Load())
	}
	lease.release()
	if pending.closeCount.Load() != 1 {
		t.Fatal("second release double-closed pending egress")
	}
}

func TestAdoptTCPFlowFailureClosesPendingEgressOnce(t *testing.T) {
	c := newOwnershipTestPlane()
	manager := NewSessionManager(context.Background())
	if err := manager.Close(); err != nil {
		t.Fatalf("manager Close: %v", err)
	}
	c.sessionManagerBinding.Store(&controlPlaneSessionManagerBinding{manager: manager})

	ingress, peer := net.Pipe()
	t.Cleanup(func() {
		_ = ingress.Close()
		_ = peer.Close()
	})
	lease, ok := c.acquireIncomingConnectionLease(ingress)
	if !ok {
		t.Fatal("acquireIncomingConnectionLease rejected")
	}
	pending := &closeCountConn{}
	lease.storePendingEgress(pending)

	_, err := c.adoptTCPFlow(
		context.Background(), lease, ingress, pending, TcpFlowBinding{},
		netip.MustParseAddrPort("127.0.0.1:10000"),
		netip.MustParseAddrPort("127.0.0.1:20000"),
	)
	if !errors.Is(err, ErrSessionManagerClosed) {
		t.Fatalf("adoptTCPFlow error = %v, want ErrSessionManagerClosed", err)
	}
	if pending.closeCount.Load() != 1 {
		t.Fatalf("adopt failure close count = %d, want 1", pending.closeCount.Load())
	}
	lease.release()
	if pending.closeCount.Load() != 1 {
		t.Fatal("lease release double-closed failed adoption egress")
	}
}

func TestAdoptTCPFlowFailureDoesNotCloseAbortOwnedEgress(t *testing.T) {
	c := newOwnershipTestPlane()
	manager := NewSessionManager(context.Background())
	if err := manager.Close(); err != nil {
		t.Fatalf("manager Close: %v", err)
	}
	c.sessionManagerBinding.Store(&controlPlaneSessionManagerBinding{manager: manager})

	ingress, peer := net.Pipe()
	t.Cleanup(func() {
		_ = ingress.Close()
		_ = peer.Close()
	})
	lease, ok := c.acquireIncomingConnectionLease(ingress)
	if !ok {
		t.Fatal("acquireIncomingConnectionLease rejected")
	}
	pending := &closeCountConn{}
	lease.storePendingEgress(pending)
	abortOwned := lease.takePendingEgress()
	if abortOwned == nil {
		t.Fatal("abort did not claim pending egress")
	}

	_, err := c.adoptTCPFlow(
		context.Background(), lease, ingress, pending, TcpFlowBinding{},
		netip.MustParseAddrPort("127.0.0.1:10001"),
		netip.MustParseAddrPort("127.0.0.1:20001"),
	)
	if !errors.Is(err, ErrSessionManagerClosed) {
		t.Fatalf("adoptTCPFlow error = %v, want ErrSessionManagerClosed", err)
	}
	if pending.closeCount.Load() != 0 {
		t.Fatal("adopt failure closed egress already owned by abort")
	}
	_ = abortOwned.Close()
	lease.release()
	if pending.closeCount.Load() != 1 {
		t.Fatalf("final close count = %d, want 1", pending.closeCount.Load())
	}
}

func TestHandleConnDoesNotDoubleCloseFailedAdoption(t *testing.T) {
	src, err := os.ReadFile("tcp.go")
	if err != nil {
		t.Fatalf("read tcp.go: %v", err)
	}
	text := string(src)
	marker := "flow, err := c.adoptTCPFlow(ctx, ownership, ingressConn, rConn, binding, src, dst)"
	idx := strings.Index(text, marker)
	if idx < 0 {
		t.Fatal("handleConn adoptTCPFlow call missing")
	}
	window := text[idx:]
	before, _, ok := strings.Cut(window, "defer closeEstablishedTCPFlow")
	if !ok {
		t.Fatal("successful adoption ownership boundary missing")
	}
	if strings.Contains(before, "rConn.Close()") {
		t.Fatal("handleConn closes egress already claimed by adopt failure ownership")
	}
}

func TestStopRoutingEpochExecutionTimeoutContinues(t *testing.T) {
	logBuf := bytes.NewBuffer(nil)
	logger := logrus.New()
	logger.SetOutput(logBuf)
	logger.SetLevel(logrus.WarnLevel)
	c := newOwnershipTestPlane()
	c.log = logger
	hold := c.drainTracker.Acquire()
	t.Cleanup(hold)

	started := time.Now()
	done := make(chan struct{})
	go func() {
		c.StopRoutingEpochExecutionWithTimeout(30 * time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("StopRoutingEpochExecutionWithTimeout blocked past the bound")
	}
	if time.Since(started) > 400*time.Millisecond {
		t.Fatalf("timeout path took %v, want ~30ms", time.Since(started))
	}
	if !bytes.Contains(logBuf.Bytes(), []byte("routing epoch drain wait timed out; continuing retirement")) {
		t.Fatalf("timeout warn missing, log=%q", logBuf.String())
	}
	if c.drainTracker.Count() != 1 {
		t.Fatal("timeout path must not AbortConnections / drop the held ticket")
	}
}

func TestShouldSkipDNSFastPathForLocalListenerTraffic(t *testing.T) {
	loopbackSrc := netip.MustParseAddrPort("127.0.0.1:53000")
	loopbackDst := netip.MustParseAddrPort("127.0.0.1:53")
	lanSrc := netip.MustParseAddrPort("192.168.1.10:53000")
	lanDst := netip.MustParseAddrPort("192.168.1.1:53")
	publicDst := netip.MustParseAddrPort("1.1.1.1:53")

	if !shouldSkipDNSFastPathForLocalListenerTraffic("127.0.0.1:53", loopbackSrc, loopbackDst) {
		t.Fatal("loopback self-query must skip NAT tracking")
	}
	if shouldSkipDNSFastPathForLocalListenerTraffic("192.168.1.1:53", lanSrc, lanDst) {
		t.Fatal("LAN client query of LAN-bound listener must stay on DNS fast path")
	}
	if !shouldSkipDNSFastPathForLocalListenerTraffic("192.168.1.1:53", loopbackSrc, lanDst) {
		t.Fatal("loopback src to LAN listener must skip")
	}
	if shouldSkipDNSFastPathForLocalListenerTraffic("127.0.0.1:53", lanSrc, publicDst) {
		t.Fatal("ordinary public DNS must not skip")
	}
	if shouldSkipDNSFastPathForLocalListenerTraffic("", loopbackSrc, loopbackDst) {
		t.Fatal("empty listen addr must not skip")
	}
}

func TestSkipTrueDoesNotReturnFromDNSFastPath(t *testing.T) {
	src, err := os.ReadFile("udp_ingress_task.go")
	if err != nil {
		t.Fatalf("read udp_ingress_task.go: %v", err)
	}
	text := string(src)
	marker := "if shouldSkipDNSFastPathForLocalListenerTraffic(listenAddr, convergeSrc, realDst)"
	idx := strings.Index(text, marker)
	if idx < 0 {
		t.Fatal("skip predicate call missing from udpIngressTask.Run")
	}
	window := text[idx:]
	before, _, ok := strings.Cut(window, "if dnsMessage, _ := ChooseNatTimeout")
	if !ok {
		t.Fatal("DNS fast path after skip block is missing")
	}
	block := before
	if strings.Contains(block, "return") {
		t.Fatal("skip-true branch returns and drops TProxy-reached local DNS")
	}

	loopbackSrc := netip.MustParseAddrPort("127.0.0.1:53000")
	loopbackDst := netip.MustParseAddrPort("127.0.0.1:53")
	if !shouldSkipDNSFastPathForLocalListenerTraffic("127.0.0.1:53", loopbackSrc, loopbackDst) {
		t.Fatal("fixture skip predicate must be true")
	}
}

func TestUDPWriteBatchUnflushedFirstSurvivesHealthInvalidation(t *testing.T) {
	rec := &batchRecorder{}
	ue := newBatchTestEndpoint(rec)
	agg := newUDPWriteBatchAggregator(ue)
	ue.writeBatch = agg
	if err := agg.Append([]byte("first"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !agg.hasUnflushedFirst() {
		t.Fatal("queued first datagram must set unflushedFirst")
	}
	if !ue.survivesDialerHealthInvalidation() {
		t.Fatal("queued-unflushed first packet must survive health invalidation")
	}
	agg.Close()
}

func discardLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return logger
}

type closeCountConn struct {
	closeCount atomic.Int32
}

func (c *closeCountConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *closeCountConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *closeCountConn) Close() error {
	c.closeCount.Add(1)
	return nil
}
func (c *closeCountConn) SetDeadline(time.Time) error      { return nil }
func (c *closeCountConn) SetReadDeadline(time.Time) error  { return nil }
func (c *closeCountConn) SetWriteDeadline(time.Time) error { return nil }
