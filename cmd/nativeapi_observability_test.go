/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/sirupsen/logrus"
)

func TestFrameHubReplayAndCursorExpiry(t *testing.T) {
	hub := newFrameHub("instance-1", "events", 8, time.Minute, 4)
	hub.publish("generation.changed", map[string]any{"generation_id": "gen-1"})
	hub.publish("operation.updated", map[string]any{"resource_id": "op-1"})

	stream, err := hub.open("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(stream.Replay) != 2 {
		t.Fatalf("replay = %d, want 2", len(stream.Replay))
	}
	lastID := stream.Replay[len(stream.Replay)-1].ID

	resumed, err := hub.open(lastID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(resumed.Replay) != 0 {
		t.Fatalf("resume replay = %d, want 0", len(resumed.Replay))
	}

	if _, err := hub.open("events:does-not-exist", nil); err == nil {
		t.Fatal("unknown cursor must fail")
	}
}

func TestFrameHubFilterAndRingBounded(t *testing.T) {
	hub := newFrameHub("instance-1", "events", 2, time.Minute, 4)
	hub.publish("generation.changed", map[string]any{})
	hub.publish("operation.updated", map[string]any{})
	hub.publish("generation.changed", map[string]any{})

	stream, err := hub.open("", func(event string, _ any) bool { return event == "operation.updated" })
	if err != nil {
		t.Fatal(err)
	}
	if len(stream.Replay) != 1 || stream.Replay[0].Event != "operation.updated" {
		t.Fatalf("filtered replay = %#v", stream.Replay)
	}
	if hub.length != 2 {
		t.Fatalf("ring length = %d, want 2", hub.length)
	}
}

func TestLogHubSanitizesSecrets(t *testing.T) {
	hub := newFrameHub("instance-1", "logs", 8, time.Minute, 0)
	hook := &logHubHook{hub: hub}
	entry := newTestLogEntry("Authorization: Bearer abc.def and token=xyz")
	entry.Data["secret"] = "must-not-leak"
	entry.Data["url"] = "https://example.com/x?token=abc"
	if err := hook.Fire(entry); err != nil {
		t.Fatal(err)
	}
	stream, err := hub.open("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(stream.Replay) != 1 {
		t.Fatalf("replay = %d", len(stream.Replay))
	}
	record := stream.Replay[0].Data.(nativeapi.LogRecord)
	if record.Fields["secret"] != nil {
		t.Fatal("secret field must be dropped")
	}
	if message := record.Message; message != "Authorization: Bearer [redacted] and token=xyz" {
		t.Fatalf("message = %q", message)
	}
	if url, _ := record.Fields["url"].(string); url != "https://example.com/x?[redacted]" {
		t.Fatalf("url = %q", url)
	}
}

func newTestLogEntry(message string) *logrus.Entry {
	logger := logrus.New()
	entry := logrus.NewEntry(logger)
	entry.Message = message
	entry.Level = logrus.InfoLevel
	entry.Time = time.Now()
	return entry
}

func TestFrameHubEmptyStreamCursorResumes(t *testing.T) {
	hub := newFrameHub("instance-1", "events", 4, time.Minute, 2)
	stream, err := hub.open("", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Cancel()
	if stream.Ready.ID != "events:0" {
		t.Fatalf("ready id = %q, want events:0", stream.Ready.ID)
	}
	// A client that attached to an empty stream must be able to resume with the
	// cursor it was given, even though no frame carries that ID.
	emptyResume, err := hub.open(stream.Ready.ID, nil)
	if err != nil {
		t.Fatalf("resume from empty-stream cursor: %v", err)
	}
	emptyResume.Cancel()
	hub.publish("runtime.updated", map[string]any{"observed_at": "2026-01-01T00:00:00Z"})
	resumed, err := hub.open(stream.Ready.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Cancel()
	if len(resumed.Replay) != 1 || resumed.Replay[0].ID != "events:1" {
		t.Fatalf("replay = %+v, want the frame published after the empty cursor", resumed.Replay)
	}
}

func TestFrameHubZeroCapacityDoesNotPanic(t *testing.T) {
	hub := newFrameHub("instance-1", "logs", 0, 0, 0)
	hub.publish("log.record", map[string]any{"seq": 1})
	stream, err := hub.open("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(stream.Replay) != 1 {
		t.Fatalf("replay = %d, want 1", len(stream.Replay))
	}
}
