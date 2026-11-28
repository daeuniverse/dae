/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
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

// A connection that is still open lives in the active snapshot, not in the
// closed history. Filtering the list by its connection_id used to answer an
// empty list even though GET /flows/{id} returned the flow.
func TestFlowListConnectionIDIncludesActiveFlows(t *testing.T) {
	active := control.SessionFlowSnapshot{ID: "f_active", Network: "tcp"}
	history := []control.SessionFlowHistoryEntry{
		{SessionFlowSnapshot: control.SessionFlowSnapshot{ID: "f_closed", Network: "tcp"}, State: "closed"},
	}
	filter := nativeapi.FlowFilter{ConnectionID: connectionIDOfFlow(active.ID)}
	matched := matchingFlows([]control.SessionFlowSnapshot{active}, history, filter)
	if len(matched) != 1 {
		t.Fatalf("matched %d flows, want the active one: %+v", len(matched), matched)
	}
	if matched[0].ID != active.ID || matched[0].State != "active" {
		t.Fatalf("matched = %+v, want the active flow", matched[0])
	}
	// A closed flow with the same filter is still found, and the exact id
	// match keeps the other flow out of both walks.
	if got := matchingFlows(nil, history, nativeapi.FlowFilter{ConnectionID: connectionIDOfFlow("f_closed")}); len(got) != 1 || got[0].ID != "f_closed" {
		t.Fatalf("closed connection filter = %+v", got)
	}
	if got := matchingFlows([]control.SessionFlowSnapshot{active}, history, nativeapi.FlowFilter{ConnectionID: "c_other"}); len(got) != 0 {
		t.Fatalf("unknown connection filter matched %+v", got)
	}
}

func TestNativeFlowJSONUnknownRule(t *testing.T) {
	flow := flowWithBytes()
	provider := &nativeAPIProvider{}
	check := func(t *testing.T, value any, wantGeneration bool) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var row map[string]json.RawMessage
		if err := json.Unmarshal(data, &row); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"rule_id", "rule_expression"} {
			if string(row[key]) != "null" {
				t.Errorf("%s = %s, want an explicit null", key, row[key])
			}
		}
		if got, present := row["rule_generation_id"]; wantGeneration {
			if string(got) != "null" {
				t.Errorf("rule_generation_id = %s, want an explicit null", got)
			}
		} else if present {
			t.Errorf("connection includes rule_generation_id: %s", got)
		}
		if string(row["rule_source"]) != `"unknown"` {
			t.Errorf("rule_source = %s, want unknown", row["rule_source"])
		}
	}
	t.Run("connection", func(t *testing.T) {
		check(t, provider.nativeConnectionOf(flow), false)
	})
	for _, state := range []string{"active", "closed"} {
		summary := nativeFlowSummary(control.SessionFlowHistoryEntry{
			SessionFlowSnapshot: flow,
			State:               state,
		}, "fixture")
		t.Run(state+"/summary", func(t *testing.T) { check(t, summary, true) })
		t.Run(state+"/detail", func(t *testing.T) {
			check(t, nativeapi.FlowDetail{FlowSummary: summary, Input: summary.Input}, true)
		})
	}
}
