/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/control"
)

func flowWithBytes() control.SessionFlowSnapshot {
	return control.SessionFlowSnapshot{
		ID:            "f_1",
		Network:       "tcp",
		Domain:        "example.com",
		StartedAt:     time.Now(),
		UploadBytes:   2048,
		DownloadBytes: 1048576,
		HasBytes:      true,
	}
}

func TestConnectionBytesReportedByDefault(t *testing.T) {
	p := &nativeAPIProvider{connectionBytes: true}

	connection := p.nativeConnectionOf(flowWithBytes())
	if connection.UploadBytes == nil || connection.DownloadBytes == nil {
		t.Fatalf("bytes should be reported: up=%v down=%v", connection.UploadBytes, connection.DownloadBytes)
	}
	if got := *connection.UploadBytes; got != "2048" {
		t.Fatalf("upload_bytes = %q, want 2048", got)
	}
}

func TestConnectionBytesDroppedWhenDisabled(t *testing.T) {
	// Only userspace flows carry counters, so a total aggregated from them
	// covers a fraction of the traffic. Dropping the fields keeps every other
	// connection attribute intact and leaves the totals null.
	p := &nativeAPIProvider{connectionBytes: false}

	connection := p.nativeConnectionOf(flowWithBytes())
	if connection.UploadBytes != nil || connection.DownloadBytes != nil {
		t.Fatalf("bytes must stay null: up=%v down=%v", connection.UploadBytes, connection.DownloadBytes)
	}
	if connection.Domain == nil || *connection.Domain != "example.com" {
		t.Fatalf("domain must survive: %v", connection.Domain)
	}
}

func TestConnectionBytesAbsentForFlowsWithoutCounters(t *testing.T) {
	p := &nativeAPIProvider{connectionBytes: true}
	flow := flowWithBytes()
	flow.HasBytes = false

	connection := p.nativeConnectionOf(flow)
	if connection.UploadBytes != nil || connection.DownloadBytes != nil {
		t.Fatalf("a flow without counters must not report bytes: up=%v down=%v", connection.UploadBytes, connection.DownloadBytes)
	}
}
