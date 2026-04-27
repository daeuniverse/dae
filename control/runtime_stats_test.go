/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type mockDNSResponseWriter struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	msgs       []*dnsmessage.Msg
	rawWrites  [][]byte
}

func (w *mockDNSResponseWriter) LocalAddr() net.Addr  { return w.localAddr }
func (w *mockDNSResponseWriter) RemoteAddr() net.Addr { return w.remoteAddr }
func (w *mockDNSResponseWriter) Close() error         { return nil }
func (w *mockDNSResponseWriter) TsigStatus() error    { return nil }
func (w *mockDNSResponseWriter) TsigTimersOnly(bool)  {}
func (w *mockDNSResponseWriter) Hijack()              {}

func (w *mockDNSResponseWriter) WriteMsg(msg *dnsmessage.Msg) error {
	w.msgs = append(w.msgs, msg.Copy())
	return nil
}

func (w *mockDNSResponseWriter) Write(p []byte) (int, error) {
	w.rawWrites = append(w.rawWrites, append([]byte(nil), p...))
	return len(p), nil
}

type stagedRuntimeConn struct {
	payload []byte
	release <-chan struct{}

	writeReady chan struct{}
	writeOnce  sync.Once

	writtenMu sync.Mutex
	written   bytes.Buffer
	readDone  bool
}

func newStagedRuntimeConn(payload []byte, release <-chan struct{}) *stagedRuntimeConn {
	return &stagedRuntimeConn{
		payload:    append([]byte(nil), payload...),
		release:    release,
		writeReady: make(chan struct{}),
	}
}

func (c *stagedRuntimeConn) Read(p []byte) (int, error) {
	if !c.readDone && len(c.payload) > 0 {
		c.readDone = true
		return copy(p, c.payload), nil
	}
	<-c.release
	return 0, io.EOF
}

func (c *stagedRuntimeConn) Write(p []byte) (int, error) {
	c.writtenMu.Lock()
	defer c.writtenMu.Unlock()

	n, err := c.written.Write(p)
	if n > 0 {
		c.writeOnce.Do(func() {
			close(c.writeReady)
		})
	}
	return n, err
}

func (c *stagedRuntimeConn) Close() error                       { return nil }
func (c *stagedRuntimeConn) SetDeadline(_ time.Time) error      { return nil }
func (c *stagedRuntimeConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *stagedRuntimeConn) SetWriteDeadline(_ time.Time) error { return nil }

func (c *stagedRuntimeConn) WrittenBytes() []byte {
	c.writtenMu.Lock()
	defer c.writtenMu.Unlock()
	return append([]byte(nil), c.written.Bytes()...)
}

func resetRuntimeStatsForTest(t *testing.T) {
	t.Helper()
	previous := globalRuntimeStats
	previousActive := activeRuntimeStats.Load()
	globalRuntimeStats = newRuntimeStats()
	activeRuntimeStats.Store(nil)
	t.Cleanup(func() {
		globalRuntimeStats = previous
		activeRuntimeStats.Store(previousActive)
	})
}

func TestSnapshotRuntimeStatsPreservesPublicFields(t *testing.T) {
	resetRuntimeStatsForTest(t)

	base := time.Unix(1_700_000_000, 0)
	globalRuntimeStats.record(1200, 0)
	globalRuntimeStats.roll(base.Add(400 * time.Millisecond))
	globalRuntimeStats.record(0, 800)

	snapshot := globalRuntimeStats.snapshot(3, 5, 60, 10, base.Add(900*time.Millisecond))
	if snapshot.ActiveConnections != 3 {
		t.Fatalf("ActiveConnections = %d, want 3", snapshot.ActiveConnections)
	}
	if snapshot.UDPSessions != 5 {
		t.Fatalf("UDPSessions = %d, want 5", snapshot.UDPSessions)
	}
	if snapshot.UploadTotal != 1200 {
		t.Fatalf("UploadTotal = %d, want 1200", snapshot.UploadTotal)
	}
	if snapshot.DownloadTotal != 800 {
		t.Fatalf("DownloadTotal = %d, want 800", snapshot.DownloadTotal)
	}
	if snapshot.UploadRate == 0 {
		t.Fatal("UploadRate = 0, want non-zero")
	}
	if snapshot.DownloadRate == 0 {
		t.Fatal("DownloadRate = 0, want non-zero")
	}
	if len(snapshot.Samples) == 0 {
		t.Fatal("Samples is empty, want at least one sample")
	}
	if snapshot.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt should be set")
	}
}

func TestGlobalRuntimeStatsPreferPublishedActiveStore(t *testing.T) {
	resetRuntimeStatsForTest(t)

	active := newRuntimeStats()
	publishRuntimeStatsStore(active)

	RecordUploadTraffic(123)
	RecordDownloadTraffic(45)

	snapshot := SnapshotRuntimeStats(7, 9, 60, 10)
	if snapshot.UploadTotal != 123 {
		t.Fatalf("UploadTotal = %d, want 123", snapshot.UploadTotal)
	}
	if snapshot.DownloadTotal != 45 {
		t.Fatalf("DownloadTotal = %d, want 45", snapshot.DownloadTotal)
	}
	if snapshot.ActiveConnections != 7 {
		t.Fatalf("ActiveConnections = %d, want 7", snapshot.ActiveConnections)
	}
	if snapshot.UDPSessions != 9 {
		t.Fatalf("UDPSessions = %d, want 9", snapshot.UDPSessions)
	}
	if globalRuntimeStats.uploadTotal.Load() != 0 {
		t.Fatalf("global upload total = %d, want 0", globalRuntimeStats.uploadTotal.Load())
	}
	if globalRuntimeStats.downloadTotal.Load() != 0 {
		t.Fatalf("global download total = %d, want 0", globalRuntimeStats.downloadTotal.Load())
	}
}

func TestGlobalRuntimeStatsFallbackAfterUnpublish(t *testing.T) {
	resetRuntimeStatsForTest(t)

	active := newRuntimeStats()
	publishRuntimeStatsStore(active)
	unpublishRuntimeStatsStore(active)

	RecordUploadTraffic(11)
	RecordDownloadTraffic(13)

	snapshot := SnapshotRuntimeStats(1, 2, 60, 10)
	if snapshot.UploadTotal != 11 {
		t.Fatalf("UploadTotal = %d, want 11", snapshot.UploadTotal)
	}
	if snapshot.DownloadTotal != 13 {
		t.Fatalf("DownloadTotal = %d, want 13", snapshot.DownloadTotal)
	}
	if active.uploadTotal.Load() != 0 {
		t.Fatalf("active upload total = %d, want 0", active.uploadTotal.Load())
	}
	if active.downloadTotal.Load() != 0 {
		t.Fatalf("active download total = %d, want 0", active.downloadTotal.Load())
	}
}

func TestUnpublishRuntimeStatsStoreDoesNotClearNewerActiveStore(t *testing.T) {
	resetRuntimeStatsForTest(t)

	oldActive := newRuntimeStats()
	newActive := newRuntimeStats()
	publishRuntimeStatsStore(oldActive)
	publishRuntimeStatsStore(newActive)
	unpublishRuntimeStatsStore(oldActive)

	RecordUploadTraffic(19)

	if newActive.uploadTotal.Load() != 19 {
		t.Fatalf("new active upload total = %d, want 19", newActive.uploadTotal.Load())
	}
	if activeRuntimeStats.Load() != newActive {
		t.Fatal("active runtime stats store changed, want newer active store to remain published")
	}
}

func TestActivatePreparedRuntimePublishesStatsBeforeDNSStart(t *testing.T) {
	resetRuntimeStatsForTest(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cp := &ControlPlane{
		ctx:          ctx,
		runtimeStats: newRuntimeStats(),
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			delayDNSListenerStart: true,
		},
	}
	cp.SetPreparedDNSStartHook(func() error {
		if activeRuntimeStats.Load() != cp.runtimeStats {
			return errors.New("runtime stats not published before DNS start hook")
		}
		RecordUploadTraffic(11)
		RecordDownloadTraffic(13)
		return nil
	})
	defer cp.unpublishRuntimeStats()

	if err := cp.activatePreparedRuntime(); err != nil {
		t.Fatalf("activatePreparedRuntime() error = %v", err)
	}

	snapshot := cp.SnapshotRuntimeStats(60, 10)
	if snapshot.UploadTotal != 11 {
		t.Fatalf("UploadTotal = %d, want 11", snapshot.UploadTotal)
	}
	if snapshot.DownloadTotal != 13 {
		t.Fatalf("DownloadTotal = %d, want 13", snapshot.DownloadTotal)
	}
	if activeRuntimeStats.Load() != cp.runtimeStats {
		t.Fatal("active runtime stats store not published to control-plane runtime stats")
	}
}

func TestActivatePreparedRuntimeUnpublishesOnDNSStartError(t *testing.T) {
	resetRuntimeStatsForTest(t)

	wantErr := errors.New("boom")
	cp := &ControlPlane{
		ctx:          context.Background(),
		runtimeStats: newRuntimeStats(),
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			delayDNSListenerStart: true,
		},
	}
	cp.SetPreparedDNSStartHook(func() error {
		return wantErr
	})

	err := cp.activatePreparedRuntime()
	if !errors.Is(err, wantErr) {
		t.Fatalf("activatePreparedRuntime() error = %v, want %v", err, wantErr)
	}
	if activeRuntimeStats.Load() != nil {
		t.Fatal("active runtime stats store should be unpublished after DNS start failure")
	}

	RecordUploadTraffic(7)
	if got := cp.runtimeStats.uploadTotal.Load(); got != 0 {
		t.Fatalf("control-plane upload total = %d, want 0 after failed activation", got)
	}
	if got := globalRuntimeStats.uploadTotal.Load(); got != 7 {
		t.Fatalf("global upload total = %d, want 7 after failed activation fallback", got)
	}
}

func TestRuntimeStatsConcurrentRecordsKeepExactTotals(t *testing.T) {
	var stats runtimeStats
	base := time.Unix(1_700_000_000, 0)

	const (
		goroutines = 32
		iterations = 1000
	)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range iterations {
				stats.record(1, 2)
			}
		}()
	}
	wg.Wait()

	snapshot := stats.snapshot(0, 0, 60, 10, base.Add(10*time.Millisecond))
	wantUpload := uint64(goroutines * iterations)
	wantDownload := uint64(goroutines * iterations * 2)
	if snapshot.UploadTotal != wantUpload {
		t.Fatalf("UploadTotal = %d, want %d", snapshot.UploadTotal, wantUpload)
	}
	if snapshot.DownloadTotal != wantDownload {
		t.Fatalf("DownloadTotal = %d, want %d", snapshot.DownloadTotal, wantDownload)
	}
}

func TestRuntimeStatsHistoryAllocatedLazily(t *testing.T) {
	stats := newRuntimeStats()
	if len(stats.history) != 0 {
		t.Fatalf("newRuntimeStats allocated %d history buckets, want lazy allocation", len(stats.history))
	}

	base := time.Unix(1_700_000_000, 0)
	stats.record(1, 0)
	if len(stats.history) != 0 {
		t.Fatalf("initial bucket allocated %d history buckets, want none", len(stats.history))
	}

	stats.roll(base)
	stats.roll(base.Add(runtimeBucketDuration))
	if len(stats.history) != maxRuntimeHistoryBuckets() {
		t.Fatalf("history buckets = %d, want %d", len(stats.history), maxRuntimeHistoryBuckets())
	}
}

func TestRuntimeStatsIdleRollDoesNotAllocateHistory(t *testing.T) {
	stats := newRuntimeStats()
	base := time.Unix(1_700_000_000, 0)

	stats.roll(base)
	stats.roll(base.Add(10 * runtimeBucketDuration))
	if len(stats.history) != 0 {
		t.Fatalf("idle roll allocated %d history buckets, want none", len(stats.history))
	}
}

func TestControlPlaneRuntimeStatsRemainIsolatedPerInstance(t *testing.T) {
	planeA := &ControlPlane{runtimeStats: newRuntimeStats()}
	planeB := &ControlPlane{runtimeStats: newRuntimeStats()}

	planeA.recordUploadTraffic(100)
	planeA.recordDownloadTraffic(40)
	planeB.recordUploadTraffic(7)
	planeB.recordDownloadTraffic(9)

	snapshotA := planeA.SnapshotRuntimeStats(60, 10)
	snapshotB := planeB.SnapshotRuntimeStats(60, 10)

	if snapshotA.UploadTotal != 100 || snapshotA.DownloadTotal != 40 {
		t.Fatalf("planeA totals = (%d, %d), want (100, 40)", snapshotA.UploadTotal, snapshotA.DownloadTotal)
	}
	if snapshotB.UploadTotal != 7 || snapshotB.DownloadTotal != 9 {
		t.Fatalf("planeB totals = (%d, %d), want (7, 9)", snapshotB.UploadTotal, snapshotB.DownloadTotal)
	}
}

func TestRelayTCPRecordsRuntimeTrafficTotals(t *testing.T) {
	resetRuntimeStatsForTest(t)

	uploadPayload := []byte("hello upstream")
	downloadPayload := []byte("hello downstream")

	left := newCopyEngineMockConnFromBytes(uploadPayload)
	right := newCopyEngineMockConnFromBytes(downloadPayload)

	if err := RelayTCP(left, right); err != nil {
		t.Fatalf("RelayTCP() error = %v", err)
	}

	snapshot := SnapshotRuntimeStats(0, 0, 60, 10)
	if got, want := snapshot.UploadTotal, uint64(len(uploadPayload)); got != want {
		t.Fatalf("UploadTotal = %d, want %d", got, want)
	}
	if got, want := snapshot.DownloadTotal, uint64(len(downloadPayload)); got != want {
		t.Fatalf("DownloadTotal = %d, want %d", got, want)
	}
	if !bytes.Equal(right.writer.Bytes(), uploadPayload) {
		t.Fatalf("right payload = %q, want %q", right.writer.Bytes(), uploadPayload)
	}
	if !bytes.Equal(left.writer.Bytes(), downloadPayload) {
		t.Fatalf("left payload = %q, want %q", left.writer.Bytes(), downloadPayload)
	}
}

func TestRelayTCPRecordsRuntimeTrafficBeforeClose(t *testing.T) {
	resetRuntimeStatsForTest(t)

	uploadPayload := []byte("streaming upload payload")
	release := make(chan struct{})
	left := newStagedRuntimeConn(uploadPayload, release)
	right := newStagedRuntimeConn(nil, release)

	errCh := make(chan error, 1)
	go func() {
		errCh <- RelayTCP(left, right)
	}()

	select {
	case <-right.writeReady:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for relay write")
	}

	wantUpload := uint64(len(uploadPayload))
	deadline := time.Now().Add(time.Second)
	for {
		snapshot := SnapshotRuntimeStats(0, 0, 60, 10)
		if snapshot.UploadTotal == wantUpload {
			if snapshot.DownloadTotal != 0 {
				t.Fatalf("DownloadTotal = %d, want 0", snapshot.DownloadTotal)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("UploadTotal did not update before relay close: got %d want %d", snapshot.UploadTotal, wantUpload)
		}
		time.Sleep(10 * time.Millisecond)
	}

	close(release)
	if err := <-errCh; err != nil {
		t.Fatalf("RelayTCP() error = %v", err)
	}
	if !bytes.Equal(right.WrittenBytes(), uploadPayload) {
		t.Fatalf("right payload = %q, want %q", right.WrittenBytes(), uploadPayload)
	}
}

func TestControlPlaneActiveTCPConnectionsMatchesTrackedConnections(t *testing.T) {
	var plane ControlPlane

	leftA, rightA := net.Pipe()
	leftB, rightB := net.Pipe()
	defer func() {
		_ = leftA.Close()
		_ = rightA.Close()
		_ = leftB.Close()
		_ = rightB.Close()
	}()

	if !plane.registerIncomingConnection(leftA) {
		t.Fatal("registerIncomingConnection(leftA) = false, want true")
	}
	if !plane.registerIncomingConnection(leftB) {
		t.Fatal("registerIncomingConnection(leftB) = false, want true")
	}
	if got := plane.ActiveTCPConnections(); got != 2 {
		t.Fatalf("ActiveTCPConnections() = %d, want 2", got)
	}

	plane.unregisterIncomingConnection(leftA)
	if got := plane.ActiveTCPConnections(); got != 1 {
		t.Fatalf("ActiveTCPConnections() after unregister = %d, want 1", got)
	}
}

func TestHandleTCPDnsFastPathRecordsRuntimeTraffic(t *testing.T) {
	resetRuntimeStatsForTest(t)

	ctrl := newScopedDnsController(t)
	log := logrus.New()
	log.SetOutput(io.Discard)
	plane := &ControlPlane{
		log: log,
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsController: ctrl,
		},
	}

	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	query := new(dnsmessage.Msg)
	query.SetQuestion("example.com.", dnsmessage.TypeA)
	queryPayload, err := query.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	queryFrame := make([]byte, 2+len(queryPayload))
	binary.BigEndian.PutUint16(queryFrame[:2], uint16(len(queryPayload)))
	copy(queryFrame[2:], queryPayload)

	resultCh := make(chan struct {
		handled bool
		err     error
	}, 1)
	go func() {
		handled, err := plane.handleTCPDnsFastPath(
			context.Background(),
			serverConn,
			bufio.NewReader(serverConn),
			netip.MustParseAddrPort("127.0.0.1:12345"),
			netip.MustParseAddrPort("8.8.8.8:53"),
			&bpfRoutingResult{},
		)
		resultCh <- struct {
			handled bool
			err     error
		}{handled: handled, err: err}
	}()

	if _, err := clientConn.Write(queryFrame); err != nil {
		t.Fatalf("Write(queryFrame) error = %v", err)
	}

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, lenBuf); err != nil {
		t.Fatalf("ReadFull(length) error = %v", err)
	}
	respLen := binary.BigEndian.Uint16(lenBuf)
	respPayload := make([]byte, respLen)
	if _, err := io.ReadFull(clientConn, respPayload); err != nil {
		t.Fatalf("ReadFull(payload) error = %v", err)
	}

	var resp dnsmessage.Msg
	if err := resp.Unpack(respPayload); err != nil {
		t.Fatalf("Unpack(response) error = %v", err)
	}
	if resp.Rcode != dnsmessage.RcodeServerFailure {
		t.Fatalf("response rcode = %d, want %d", resp.Rcode, dnsmessage.RcodeServerFailure)
	}

	_ = clientConn.Close()
	result := <-resultCh
	if result.err != nil {
		t.Fatalf("handleTCPDnsFastPath() error = %v", result.err)
	}
	if !result.handled {
		t.Fatal("handleTCPDnsFastPath() handled = false, want true")
	}

	snapshot := SnapshotRuntimeStats(0, 0, 60, 10)
	if got, want := snapshot.UploadTotal, uint64(len(queryFrame)); got != want {
		t.Fatalf("UploadTotal = %d, want %d", got, want)
	}
	if got, want := snapshot.DownloadTotal, uint64(2+len(respPayload)); got != want {
		t.Fatalf("DownloadTotal = %d, want %d", got, want)
	}
}

func TestWriteRuntimeTrackedUDPAddrPortRecordsDownloadTraffic(t *testing.T) {
	resetRuntimeStatsForTest(t)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(server) error = %v", err)
	}
	defer func() { _ = serverConn.Close() }()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client) error = %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	payload := []byte("dns-response")
	if err := writeRuntimeTrackedUDPAddrPort(serverConn, payload, clientConn.LocalAddr().(*net.UDPAddr).AddrPort(), RecordDownloadTraffic); err != nil {
		t.Fatalf("writeRuntimeTrackedUDPAddrPort() error = %v", err)
	}

	buf := make([]byte, 64)
	n, _, err := clientConn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("ReadFromUDPAddrPort() error = %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("received payload = %q, want %q", buf[:n], payload)
	}

	snapshot := SnapshotRuntimeStats(0, 0, 60, 10)
	if got, want := snapshot.DownloadTotal, uint64(len(payload)); got != want {
		t.Fatalf("DownloadTotal = %d, want %d", got, want)
	}
}

func TestSendRuntimeTrackedPktLegacyAnyfromRecordsDownloadTrafficAndPreservesSource(t *testing.T) {
	resetRuntimeStatsForTest(t)

	oldAnyfromPool := DefaultAnyfromPool
	DefaultAnyfromPool = newTestAnyfromPoolWithoutJanitor()
	defer func() {
		DefaultAnyfromPool.Reset()
		DefaultAnyfromPool = oldAnyfromPool
	}()

	replyConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(reply) error = %v", err)
	}
	defer func() { _ = replyConn.Close() }()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client) error = %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	replyAddr := replyConn.LocalAddr().(*net.UDPAddr).AddrPort()
	clientAddr := clientConn.LocalAddr().(*net.UDPAddr).AddrPort()
	af := &Anyfrom{UDPConn: replyConn, ttl: AnyfromTimeout}
	af.RefreshTtl()

	shard := DefaultAnyfromPool.shardFor(replyAddr)
	shard.mu.Lock()
	shard.pool[replyAddr] = af
	shard.mu.Unlock()

	payload := []byte("dns-response")
	if err := sendRuntimeTrackedPktLegacyAnyfrom(payload, replyAddr, clientAddr, RecordDownloadTraffic); err != nil {
		t.Fatalf("sendRuntimeTrackedPktLegacyAnyfrom() error = %v", err)
	}

	buf := make([]byte, 64)
	n, from, err := clientConn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("ReadFromUDPAddrPort() error = %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("received payload = %q, want %q", buf[:n], payload)
	}
	if from != replyAddr {
		t.Fatalf("response source = %v, want %v", from, replyAddr)
	}

	snapshot := SnapshotRuntimeStats(0, 0, 60, 10)
	if got, want := snapshot.DownloadTotal, uint64(len(payload)); got != want {
		t.Fatalf("DownloadTotal = %d, want %d", got, want)
	}
}

func TestServeDNSRecordsRuntimeTrafficForListenerPath(t *testing.T) {
	resetRuntimeStatsForTest(t)

	ctrl := newScopedDnsController(t)
	log := logrus.New()
	log.SetOutput(io.Discard)
	listener := &DNSListener{log: log}
	listener.controller.Store(&ControlPlane{
		log: log,
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsController: ctrl,
		},
	})
	handler := &dnsHandler{
		listener: listener,
		log:      log,
	}

	query := new(dnsmessage.Msg)
	query.SetQuestion("example.com.", dnsmessage.TypeA)
	writer := &mockDNSResponseWriter{
		localAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53},
		remoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000},
	}

	handler.ServeDNS(writer, query)

	if len(writer.msgs) != 1 {
		t.Fatalf("responses = %d, want 1", len(writer.msgs))
	}
	resp := writer.msgs[0]
	if resp.Rcode != dnsmessage.RcodeServerFailure {
		t.Fatalf("response rcode = %d, want %d", resp.Rcode, dnsmessage.RcodeServerFailure)
	}

	snapshot := SnapshotRuntimeStats(0, 0, 60, 10)
	if got, want := snapshot.UploadTotal, uint64(query.Len()); got != want {
		t.Fatalf("UploadTotal = %d, want %d", got, want)
	}
	if got, want := snapshot.DownloadTotal, uint64(resp.Len()); got != want {
		t.Fatalf("DownloadTotal = %d, want %d", got, want)
	}
}

func TestRuntimeTrackedDNSResponseWriterRecordsTCPFrameLength(t *testing.T) {
	resetRuntimeStatsForTest(t)

	base := &mockDNSResponseWriter{
		localAddr:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53},
		remoteAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000},
	}
	writer := wrapRuntimeTrackedDNSResponseWriter(base, RecordDownloadTraffic)
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)

	if err := writer.WriteMsg(msg); err != nil {
		t.Fatalf("WriteMsg() error = %v", err)
	}

	snapshot := SnapshotRuntimeStats(0, 0, 60, 10)
	if got, want := snapshot.DownloadTotal, uint64(msg.Len()+2); got != want {
		t.Fatalf("DownloadTotal = %d, want %d", got, want)
	}
}
