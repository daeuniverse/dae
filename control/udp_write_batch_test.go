/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// batchRecorder implements PacketConn + PacketBatchWriter and records every
// batch (with deep-copied payloads so reuse of the aggregator buffer is safe).
func TestUDPWriteBatchRequiresExplicitOptIn(t *testing.T) {
	t.Setenv(udpWriteBatchOptInEnv, "")
	if udpWriteBatchOptedIn() {
		t.Fatal("batching enabled without explicit opt-in")
	}
	t.Setenv(udpWriteBatchOptInEnv, "1")
	if !udpWriteBatchOptedIn() {
		t.Fatal("batching disabled with explicit opt-in")
	}
	t.Setenv(udpWriteBatchOptInEnv, "true")
	if udpWriteBatchOptedIn() {
		t.Fatal("ambiguous opt-in value enabled batching")
	}
}

type batchRecorder struct {
	mu      sync.Mutex
	batches [][]netproxy.BatchItem
	err     error
	shortN  int // if >0, WriteBatch returns this count instead of len(items)
}

func (r *batchRecorder) WriteBatch(items []netproxy.BatchItem) (int, error) {
	clone := make([]netproxy.BatchItem, len(items))
	for i, it := range items {
		d := make([]byte, len(it.Data))
		copy(d, it.Data)
		clone[i] = netproxy.BatchItem{Data: d, Addr: it.Addr}
	}
	r.mu.Lock()
	r.batches = append(r.batches, clone)
	err := r.err
	shortN := r.shortN
	r.mu.Unlock()
	if err != nil {
		if shortN > 0 {
			return shortN, err
		}
		return 0, err
	}
	if shortN > 0 {
		return shortN, nil
	}
	return len(items), nil
}

func (r *batchRecorder) batchCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.batches)
}

func (r *batchRecorder) batch(i int) []netproxy.BatchItem {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.batches[i]
}

func (r *batchRecorder) Read([]byte) (int, error)    { return 0, io.EOF }
func (r *batchRecorder) Write(p []byte) (int, error) { return len(p), nil }
func (r *batchRecorder) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (r *batchRecorder) WriteTo(p []byte, addr string) (int, error) { return len(p), nil }
func (r *batchRecorder) Close() error                               { return nil }
func (r *batchRecorder) SetDeadline(time.Time) error                { return nil }
func (r *batchRecorder) SetReadDeadline(time.Time) error            { return nil }
func (r *batchRecorder) SetWriteDeadline(time.Time) error           { return nil }

func newBatchTestEndpoint(rec *batchRecorder) *UdpEndpoint {
	return &UdpEndpoint{conn: rec}
}

// TestAggregatorFlushOnFull: the 33rd Append flushes the first 32; the 33rd
// item is flushed by the window timer.
func TestAggregatorFlushOnFull(t *testing.T) {
	rec := &batchRecorder{}
	ue := newBatchTestEndpoint(rec)
	agg := newUDPWriteBatchAggregator(ue)

	for i := range 33 {
		if err := agg.Append([]byte{byte(i)}, "10.0.0.1:53"); err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
	}
	// The full-batch flush happens synchronously inside the 33rd Append.
	if n := rec.batchCount(); n < 1 {
		t.Fatalf("expected a flush on full batch, got %d batches", n)
	}
	first := rec.batch(0)
	if len(first) != 32 {
		t.Fatalf("expected 32 items in first batch, got %d", len(first))
	}
	for i, it := range first {
		if len(it.Data) != 1 || it.Data[0] != byte(i) {
			t.Fatalf("item %d: unexpected payload %v", i, it.Data)
		}
		if it.Addr != "10.0.0.1:53" {
			t.Fatalf("item %d: unexpected addr %q", i, it.Addr)
		}
	}
	// The trailing item is flushed by the window timer.
	deadline := time.Now().Add(2 * time.Second)
	for rec.batchCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if rec.batchCount() != 2 {
		t.Fatalf("expected timer flush for trailing item, got %d batches", rec.batchCount())
	}
	second := rec.batch(1)
	if len(second) != 1 || second[0].Data[0] != 32 {
		t.Fatalf("unexpected trailing batch: %d items, first=%v", len(second), second[0].Data)
	}
}

// TestAggregatorFlushOnTimer: a single datagram is flushed after the window.
func TestAggregatorFlushOnTimer(t *testing.T) {
	rec := &batchRecorder{}
	ue := newBatchTestEndpoint(rec)
	agg := newUDPWriteBatchAggregator(ue)

	if err := agg.Append([]byte("solo"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if rec.batchCount() != 0 {
		t.Fatal("single Append must not flush synchronously")
	}
	deadline := time.Now().Add(2 * time.Second)
	for rec.batchCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if rec.batchCount() != 1 {
		t.Fatal("expected timer flush")
	}
	b := rec.batch(0)
	if len(b) != 1 || string(b[0].Data) != "solo" {
		t.Fatalf("unexpected batch content: %v", b)
	}
}

// TestAggregatorBufferReuse: the backing buffer survives flushes and payloads
// are copied correctly across two full batches.
func TestAggregatorBufferReuse(t *testing.T) {
	rec := &batchRecorder{}
	ue := newBatchTestEndpoint(rec)
	agg := newUDPWriteBatchAggregator(ue)

	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i)
	}
	for round := range 2 {
		for i := range 33 {
			if err := agg.Append(payload, "10.0.0.1:53"); err != nil {
				t.Fatalf("round %d Append #%d: %v", round, i, err)
			}
		}
	}
	if rec.batchCount() < 2 {
		t.Fatalf("expected 2 full flushes, got %d", rec.batchCount())
	}
	for round := range 2 {
		b := rec.batch(round)
		if len(b) != 32 {
			t.Fatalf("round %d: expected 32 items, got %d", round, len(b))
		}
		for i, it := range b {
			if len(it.Data) != len(payload) || it.Data[0] != payload[0] || it.Data[len(payload)-1] != payload[len(payload)-1] {
				t.Fatalf("round %d item %d: payload corrupted", round, i)
			}
		}
	}
}

// TestAggregatorOversized: a datagram larger than the backing buffer falls
// back with errUDPWriteBatchOversized and does not corrupt the batch state.
func TestAggregatorOversized(t *testing.T) {
	rec := &batchRecorder{}
	ue := newBatchTestEndpoint(rec)
	agg := newUDPWriteBatchAggregator(ue)

	big := make([]byte, udpWriteBatchMaxItems*udpWriteBatchItemSize+1)
	if err := agg.Append(big, "10.0.0.1:53"); !errors.Is(err, errUDPWriteBatchOversized) {
		t.Fatalf("expected errUDPWriteBatchOversized, got %v", err)
	}
	// Aggregator still usable afterwards.
	if err := agg.Append([]byte("ok"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append after oversized: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for rec.batchCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if rec.batchCount() != 1 || len(rec.batch(0)) != 1 {
		t.Fatal("expected single-item batch after oversized fallback")
	}
}

// TestAggregatorClosed: appends after Close fail with net.ErrClosed; pending
// items are flushed on Close.
func TestAggregatorClosed(t *testing.T) {
	rec := &batchRecorder{}
	ue := newBatchTestEndpoint(rec)
	agg := newUDPWriteBatchAggregator(ue)

	if err := agg.Append([]byte("last"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	agg.Close()
	if rec.batchCount() != 1 {
		t.Fatalf("Close must flush pending items, got %d batches", rec.batchCount())
	}
	if err := agg.Append([]byte("x"), "10.0.0.1:53"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed after Close, got %v", err)
	}
}

// TestAggregatorErrorClassified: a failed WriteBatch is routed through
// handleWriteError (classified as a tolerated drop, endpoint not retired).
func TestAggregatorErrorClassified(t *testing.T) {
	rec := &batchRecorder{err: errors.New("boom")}
	ue := newBatchTestEndpoint(rec)
	agg := newUDPWriteBatchAggregator(ue)

	for i := range 33 {
		if err := agg.Append([]byte{byte(i)}, "10.0.0.1:53"); err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
	}
	if rec.batchCount() < 1 {
		t.Fatal("expected flush attempt on full batch")
	}
	if ue.dead.Load() {
		t.Fatal("tolerated flush error must not retire the endpoint")
	}
}

// TestWriteToBatchDoesNotStampSendUntilFlush: Append is not a send. WriteTo
// on a batched endpoint must leave lastSendNano/hasSent alone until flush
// actually succeeds; a failed flush must not pretend the datagram left.
func TestWriteToBatchDoesNotStampSendUntilFlush(t *testing.T) {
	rec := &batchRecorder{err: errors.New("boom")}
	ue := newBatchTestEndpoint(rec)
	ue.writeBatch = newUDPWriteBatchAggregator(ue)

	before := ue.lastSendNano.Load()
	n, err := ue.WriteTo([]byte("queued"), "10.0.0.1:53")
	if err != nil {
		t.Fatalf("WriteTo enqueue: %v", err)
	}
	if n != len("queued") {
		t.Fatalf("expected %d queued bytes, got %d", len("queued"), n)
	}
	if ue.hasSent.Load() {
		t.Fatal("hasSent must stay false until a successful flush")
	}
	if got := ue.lastSendNano.Load(); got != before {
		t.Fatalf("lastSendNano advanced on enqueue: %d -> %d", before, got)
	}

	ue.writeBatch.flush()
	if ue.hasSent.Load() {
		t.Fatal("failed flush must not set hasSent")
	}
	if got := ue.lastSendNano.Load(); got != before {
		t.Fatalf("failed flush advanced lastSendNano: %d -> %d", before, got)
	}
}

// TestWriteToBatchStampsSendAfterSuccessfulFlush: a full-batch WriteTo that
// actually leaves the socket must refresh lastSendNano/hasSent via flush().
func TestWriteToBatchStampsSendAfterSuccessfulFlush(t *testing.T) {
	rec := &batchRecorder{}
	ue := newBatchTestEndpoint(rec)
	ue.writeBatch = newUDPWriteBatchAggregator(ue)

	payload := []byte("pkt")
	n, err := ue.WriteTo(payload, "10.0.0.1:53")
	if err != nil {
		t.Fatalf("WriteTo enqueue: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("expected %d queued bytes, got %d", len(payload), n)
	}
	if ue.hasSent.Load() || rec.batchCount() != 0 {
		t.Fatal("enqueue must not flush or stamp hasSent")
	}
	ue.writeBatch.flush()
	if rec.batchCount() < 1 {
		t.Fatal("expected a flush")
	}
	if !ue.hasSent.Load() {
		t.Fatal("successful flush must set hasSent")
	}
	if ue.lastSendNano.Load() == 0 {
		t.Fatal("successful flush must refresh lastSendNano")
	}
}

// fallbackOnlyConn is a PacketConn that does not implement PacketBatchWriter,
// forcing flush() onto the synchronous WriteTo loop.
type fallbackOnlyConn struct {
	mockPacketConn
	writes int
}

func (c *fallbackOnlyConn) WriteTo(p []byte, addr string) (int, error) {
	c.writes++
	if c.writeToFn != nil {
		return c.writeToFn(p, addr)
	}
	return len(p), nil
}

func TestFallbackFlushStampsSendOnSuccess(t *testing.T) {
	conn := &fallbackOnlyConn{}
	ue := &UdpEndpoint{conn: conn}
	agg := newUDPWriteBatchAggregator(ue)
	if err := agg.Append([]byte("solo"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if ue.hasSent.Load() {
		t.Fatal("enqueue must not stamp hasSent")
	}
	agg.flush()
	if conn.writes != 1 {
		t.Fatalf("expected 1 fallback WriteTo, got %d", conn.writes)
	}
	if !ue.hasSent.Load() {
		t.Fatal("successful fallback flush must set hasSent")
	}
	if ue.lastSendNano.Load() == 0 {
		t.Fatal("successful fallback flush must refresh lastSendNano")
	}
}

func TestFallbackFlushDoesNotStampSendOnError(t *testing.T) {
	sentinel := errors.New("boom")
	conn := &fallbackOnlyConn{
		mockPacketConn: mockPacketConn{
			writeToFn: func(p []byte, addr string) (int, error) {
				return 0, sentinel
			},
		},
	}
	ue := &UdpEndpoint{conn: conn}
	agg := newUDPWriteBatchAggregator(ue)
	if err := agg.Append([]byte("solo"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	before := ue.lastSendNano.Load()
	agg.flush()
	if ue.hasSent.Load() {
		t.Fatal("failed fallback flush must not set hasSent")
	}
	if got := ue.lastSendNano.Load(); got != before {
		t.Fatalf("failed fallback flush advanced lastSendNano: %d -> %d", before, got)
	}
}

// TestFallbackFlushStampsSendOnPartialError: when some fallback datagrams
// left the socket before the first failure, the send timestamp must stay
// honest (sentAny path) even though the flush is classified as an error.
func TestFallbackFlushStampsSendOnPartialError(t *testing.T) {
	sentinel := errors.New("boom")
	var calls int
	conn := &fallbackOnlyConn{
		mockPacketConn: mockPacketConn{
			writeToFn: func(p []byte, addr string) (int, error) {
				calls++
				if calls == 2 {
					return 0, sentinel
				}
				return len(p), nil
			},
		},
	}
	ue := &UdpEndpoint{conn: conn}
	agg := newUDPWriteBatchAggregator(ue)
	if err := agg.Append([]byte("a"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append a: %v", err)
	}
	if err := agg.Append([]byte("b"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append b: %v", err)
	}
	agg.flush()
	if conn.writes != 2 {
		t.Fatalf("expected 2 fallback WriteTo calls (1 ok + 1 failed), got %d", conn.writes)
	}
	if !ue.hasSent.Load() {
		t.Fatal("partial-error fallback flush must set hasSent: one datagram left")
	}
	if ue.lastSendNano.Load() == 0 {
		t.Fatal("partial-error fallback flush must refresh lastSendNano")
	}
	if ue.dead.Load() {
		t.Fatal("first partial-error fallback flush is tolerated and must not retire")
	}
}

func TestShortWriteBatchStampsSendWhenSomeDatagramsLeft(t *testing.T) {
	rec := &batchRecorder{shortN: 1}
	ue := newBatchTestEndpoint(rec)
	agg := newUDPWriteBatchAggregator(ue)
	if err := agg.Append([]byte("a"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append a: %v", err)
	}
	if err := agg.Append([]byte("b"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append b: %v", err)
	}
	agg.flush()
	if !ue.hasSent.Load() {
		t.Fatal("short WriteBatch with n>0 must set hasSent")
	}
	if ue.lastSendNano.Load() == 0 {
		t.Fatal("short WriteBatch with n>0 must refresh lastSendNano")
	}
	if ue.dead.Load() {
		t.Fatal("first short WriteBatch is classified as a tolerated write error")
	}
}

func TestShortWriteBatchZeroDoesNotStampSend(t *testing.T) {
	rec := &batchRecorder{err: errors.New("boom")}
	ue := newBatchTestEndpoint(rec)
	agg := newUDPWriteBatchAggregator(ue)
	if err := agg.Append([]byte("solo"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	before := ue.lastSendNano.Load()
	agg.flush()
	if ue.hasSent.Load() {
		t.Fatal("failed WriteBatch with n==0 must not set hasSent")
	}
	if got := ue.lastSendNano.Load(); got != before {
		t.Fatalf("failed WriteBatch advanced lastSendNano: %d -> %d", before, got)
	}
}

// TestShortWriteBatchWithErrorStampsSendWhenSomeDatagramsLeft: a batched
// write that reports an error but still sent n>0 datagrams (the sendmmsg
// partial-failure contract) must stamp hasSent/lastSendNano — some datagrams
// really left — and count the error toward the soft-error threshold.
func TestShortWriteBatchWithErrorStampsSendWhenSomeDatagramsLeft(t *testing.T) {
	rec := &batchRecorder{err: errors.New("boom"), shortN: 1}
	ue := newBatchTestEndpoint(rec)
	agg := newUDPWriteBatchAggregator(ue)
	if err := agg.Append([]byte("a"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append a: %v", err)
	}
	if err := agg.Append([]byte("b"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append b: %v", err)
	}
	agg.flush()
	if !ue.hasSent.Load() {
		t.Fatal("error WriteBatch with n>0 must set hasSent")
	}
	if ue.lastSendNano.Load() == 0 {
		t.Fatal("error WriteBatch with n>0 must refresh lastSendNano")
	}
	if ue.dead.Load() {
		t.Fatal("first partial-error WriteBatch is tolerated and must not retire")
	}
}

// gatingBatchRecorder is a PacketBatchWriter that deliberately does NOT copy
// item payloads on WriteBatch entry. Real transports read (or encrypt) the
// payload bytes while the batch call is still in flight, and the
// netproxy.BatchItem contract requires Data to remain valid until WriteBatch
// returns. The recorder signals that it entered the call, waits for the test
// to open the gate, and only then reads the bytes — reproducing the
// mid-send buffer window the batchRecorder deep copy hides.
type gatingBatchRecorder struct {
	batchRecorder
	entered   chan struct{}
	release   chan struct{}
	done      chan struct{}
	enterOnce sync.Once
	doneOnce  sync.Once
	mu        sync.Mutex
	sent      [][]byte
}

func (r *gatingBatchRecorder) WriteBatch(items []netproxy.BatchItem) (int, error) {
	r.enterOnce.Do(func() { close(r.entered) })
	<-r.release // stays open after the first release
	for _, it := range items {
		cp := make([]byte, len(it.Data))
		copy(cp, it.Data)
		r.mu.Lock()
		r.sent = append(r.sent, cp)
		r.mu.Unlock()
	}
	r.doneOnce.Do(func() { close(r.done) })
	return len(items), nil
}

func (r *gatingBatchRecorder) sentCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sent)
}

func (r *gatingBatchRecorder) sentItem(i int) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sent[i]
}

// TestAggregatorFlushNotCorruptedByConcurrentAppend holds WriteBatch open
// (simulating a slow or proxied transport) while another flow on the same
// endpoint appends a datagram. The in-flight batch must deliver the original
// bytes: the backing buffer may not be reused until WriteBatch has returned.
func TestAggregatorFlushNotCorruptedByConcurrentAppend(t *testing.T) {
	rec := &gatingBatchRecorder{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		done:    make(chan struct{}),
	}
	ue := &UdpEndpoint{conn: rec}
	agg := newUDPWriteBatchAggregator(ue)

	first := bytes.Repeat([]byte{0xAA}, 64)
	second := bytes.Repeat([]byte{0xBB}, 64)

	if err := agg.Append(first, "10.0.0.1:53"); err != nil {
		t.Fatalf("Append first: %v", err)
	}
	go agg.flush()

	select {
	case <-rec.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("WriteBatch did not start")
	}

	// Concurrent Append from another flow sharing the endpoint. Before the
	// fix this reused the backing buffer under the in-flight batch; after
	// the fix it blocks on the aggregator mutex until the send completes.
	appendDone := make(chan error, 1)
	go func() { appendDone <- agg.Append(second, "10.0.0.2:53") }()

	// Give the appender room to (wrongly) touch the buffer mid-send.
	time.Sleep(50 * time.Millisecond)
	close(rec.release)

	select {
	case <-rec.done:
	case <-time.After(2 * time.Second):
		t.Fatal("WriteBatch did not finish")
	}
	if err := <-appendDone; err != nil {
		t.Fatalf("concurrent Append failed: %v", err)
	}

	if got := rec.sentCount(); got != 1 {
		t.Fatalf("expected 1 datagram in the in-flight batch, got %d", got)
	}
	if got := rec.sentItem(0); !bytes.Equal(got, first) {
		t.Fatalf("in-flight datagram corrupted by concurrent Append: got % x…, want all 0xAA", got[:min(8, len(got))])
	}

	// The queued datagram must still be delivered by a subsequent flush.
	agg.flush()
	if got := rec.sentCount(); got != 2 {
		t.Fatalf("expected 2 datagrams after final flush, got %d", got)
	}
	if got := rec.sentItem(1); !bytes.Equal(got, second) {
		t.Fatalf("second datagram corrupted: got % x…, want all 0xBB", got[:min(8, len(got))])
	}
}

func TestEndpointCloseBatchErrorDoesNotReenterClose(t *testing.T) {
	rec := &batchRecorder{err: net.ErrClosed}
	ue := newBatchTestEndpoint(rec)
	ue.writeBatch = newUDPWriteBatchAggregator(ue)
	if err := ue.writeBatch.Append([]byte("pending"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append: %v", err)
	}

	done := make(chan struct{})
	go func() {
		_ = ue.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("endpoint Close deadlocked after batch write error")
	}
}

func TestAggregatorCloseWaitsForActiveTimerFlush(t *testing.T) {
	rec := &gatingBatchRecorder{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		done:    make(chan struct{}),
	}
	agg := newUDPWriteBatchAggregator(&UdpEndpoint{conn: rec})
	if err := agg.Append([]byte("pending"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	// Wait for the real AfterFunc callback to enter WriteBatch. Its Timer.C is
	// nil, so Close must synchronize with the active callback through a.mu.
	select {
	case <-rec.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("timer WriteBatch did not start")
	}

	closed := make(chan struct{})
	go func() {
		agg.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close returned while WriteBatch was active")
	case <-time.After(50 * time.Millisecond):
	}
	close(rec.release)
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not finish after WriteBatch returned")
	}
	if got := rec.sentCount(); got != 1 {
		t.Fatalf("Close delivered %d datagrams, want 1", got)
	}
	if err := agg.Append([]byte("late"), "10.0.0.1:53"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Append after Close = %v, want net.ErrClosed", err)
	}
}
