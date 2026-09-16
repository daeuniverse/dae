/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"strings"
	"sync"
	"testing"

	stderrors "errors"
)

type sentReport struct {
	datagrams int
	bytes     int
}

type sentReportRecorder struct {
	mu      sync.Mutex
	reports []sentReport
}

func (r *sentReportRecorder) report(_ *UdpEndpoint, datagrams, bytes int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, sentReport{datagrams: datagrams, bytes: bytes})
}

func (r *sentReportRecorder) snapshot() []sentReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]sentReport(nil), r.reports...)
}

// TestBatchFlushReportsOnlySentDatagrams is a regression guard: a batched
// endpoint only queues datagrams in WriteTo, so the upload meter and the health
// report must be driven from the flush, with the count the transport actually
// accepted.
func TestBatchFlushReportsOnlySentDatagrams(t *testing.T) {
	rec := &batchRecorder{}
	ue := newBatchTestEndpoint(rec)
	reports := &sentReportRecorder{}
	ue.sentReporter = reports.report
	agg := newUDPWriteBatchAggregator(ue)
	ue.writeBatch = agg

	if err := agg.Append([]byte("abcd"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append first: %v", err)
	}
	if err := agg.Append([]byte("ef"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append second: %v", err)
	}
	if got := reports.snapshot(); len(got) != 0 {
		t.Fatalf("queued datagrams must not be reported before the flush: %+v", got)
	}
	if ue.hasSent.Load() {
		t.Fatal("hasSent must not be stamped by Append")
	}

	agg.flush()

	got := reports.snapshot()
	if len(got) != 1 {
		t.Fatalf("flush reports = %+v, want exactly one", got)
	}
	if got[0].datagrams != 2 || got[0].bytes != 6 {
		t.Fatalf("flush report = %+v, want {2 datagrams, 6 bytes}", got[0])
	}
	if !ue.hasSent.Load() {
		t.Fatal("a successful flush must stamp hasSent")
	}
	agg.Close()
}

// TestBatchFlushFailureIsReportedAndCounted pins the second second half: a
// failed flush used to be swallowed by the endpoint's tolerated-error policy
// (no report, no count, no log) while the caller had already counted the
// datagrams as uploaded. The failure must be counted and the partial send
// reported.
func TestBatchFlushFailureIsReportedAndCounted(t *testing.T) {
	rec := &batchRecorder{err: stderrors.New("flush boom"), shortN: 1}
	ue := newBatchTestEndpoint(rec)
	reports := &sentReportRecorder{}
	ue.sentReporter = reports.report
	agg := newUDPWriteBatchAggregator(ue)
	ue.writeBatch = agg

	before := ue.batchFlushFailureCount.Load()
	if err := agg.Append([]byte("abcd"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append first: %v", err)
	}
	if err := agg.Append([]byte("ef"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append second: %v", err)
	}
	agg.flush()

	if got := ue.batchFlushFailureCount.Load(); got != before+1 {
		t.Fatalf("batch flush failure count = %d, want %d", got, before+1)
	}
	got := reports.snapshot()
	if len(got) != 1 {
		t.Fatalf("partial flush reports = %+v, want exactly one", got)
	}
	if got[0].datagrams != 1 || got[0].bytes != 4 {
		t.Fatalf("partial flush report = %+v, want {1 datagram, 4 bytes} (the accepted prefix only)", got[0])
	}
	agg.Close()
}

// TestBatchShortWriteIsReported locks the short-write form: WriteBatch
// returning fewer datagrams than queued without an error must still be a
// reported failure.
func TestBatchShortWriteIsReported(t *testing.T) {
	rec := &batchRecorder{shortN: 1}
	ue := newBatchTestEndpoint(rec)
	agg := newUDPWriteBatchAggregator(ue)
	ue.writeBatch = agg

	before := ue.batchFlushFailureCount.Load()
	if err := agg.Append([]byte("abcd"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append first: %v", err)
	}
	if err := agg.Append([]byte("ef"), "10.0.0.1:53"); err != nil {
		t.Fatalf("Append second: %v", err)
	}
	agg.flush()

	if got := ue.batchFlushFailureCount.Load(); got != before+1 {
		t.Fatalf("short-write flush failure count = %d, want %d", got, before+1)
	}
	agg.Close()
}

// TestBatchCallerSideAccountingIsGated is the source contract for the caller
// second half: udp.go must not meter or health-report datagrams that were
// only queued into the batch aggregator.
func TestBatchCallerSideAccountingIsGated(t *testing.T) {
	src, err := os.ReadFile("udp.go")
	if err != nil {
		t.Fatalf("read udp.go: %v", err)
	}
	text := string(src)
	if !strings.Contains(text, "batchOwnsAccounting := ue.sentReporter != nil") {
		t.Fatal("udp.go must derive whether the aggregator owns the accounting")
	}
	if !strings.Contains(text, "if !batchOwnsAccounting {\n\t\t\tc.recordUploadTraffic(int64(len(payloads[packetIndex])))") {
		t.Fatal("recordUploadTraffic must be gated on the aggregator not owning the accounting")
	}
	if !strings.Contains(text, "if !batchOwnsAccounting {\n\t\tif lifecycle, ok := newUdpSessionLifecycleContext(ue, \"\"); ok {") {
		t.Fatal("reportTrafficSuccess must be gated on the aggregator not owning the accounting")
	}
}
