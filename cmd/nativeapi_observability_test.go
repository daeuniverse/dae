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
	if stream.Ready.ID != "instance-1:events:0" {
		t.Fatalf("ready id = %q, want instance-1:events:0", stream.Ready.ID)
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
	if len(resumed.Replay) != 1 || resumed.Replay[0].ID != "instance-1:events:1" {
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

func TestFrameHubCursorIsBoundToTheInstance(t *testing.T) {
	// A cursor issued by a previous process must not be accepted: the sequence
	// numbers restart, so the client would silently miss every record after the
	// restart instead of resyncing.
	oldHub := newFrameHub("instance-old", "events", 4, time.Minute, 2)
	oldHub.publish("runtime.updated", map[string]any{})
	cursor := oldHub.frameID(1)

	hub := newFrameHub("instance-new", "events", 4, time.Minute, 2)
	hub.publish("runtime.updated", map[string]any{})
	if _, err := hub.open(cursor, nil); err == nil {
		t.Fatal("a cursor from another instance must be rejected")
	} else if apiErr, ok := err.(*nativeapi.APIError); !ok || apiErr.Code != "event_cursor_expired" {
		t.Fatalf("err = %v, want event_cursor_expired", err)
	}
}

func TestFrameHubZeroCursorIsRejectedAfterEviction(t *testing.T) {
	// Two retained frames: publishing three evicts the first. A client that
	// attached before anything existed (cursor 0) has now missed a record, so
	// reporting it as up to date would drop an invalidation.
	hub := newFrameHub("instance-1", "events", 2, time.Minute, 2)
	zero := hub.frameID(0)
	for i := 0; i < 3; i++ {
		hub.publish("runtime.updated", map[string]any{})
	}
	if _, err := hub.open(zero, nil); err == nil {
		t.Fatal("a zero cursor must expire once records have been evicted")
	}
}

func TestFrameHubZeroCursorIsAcceptedWithoutEviction(t *testing.T) {
	hub := newFrameHub("instance-1", "events", 4, time.Minute, 2)
	zero := hub.frameID(0)
	hub.publish("runtime.updated", map[string]any{})
	stream, err := hub.open(zero, nil)
	if err != nil {
		t.Fatalf("zero cursor should resume while nothing was evicted: %v", err)
	}
	defer stream.Cancel()
	if len(stream.Replay) != 1 {
		t.Fatalf("replay = %d frames, want 1", len(stream.Replay))
	}
}

func TestCloseStreamsReleasesOpenStreams(t *testing.T) {
	// Shutdown waits for every open SSE handler. Closing the hubs first makes
	// those handlers return immediately instead of holding the listener for the
	// whole grace period.
	hub := newFrameHub("instance-1", "events", 4, time.Minute, 4)
	stream, err := hub.open("", nil)
	if err != nil {
		t.Fatal(err)
	}
	provider := &nativeAPIProvider{eventHub: hub, logHub: newFrameHub("instance-1", "logs", 4, time.Minute, 4)}
	provider.CloseStreams()

	select {
	case _, ok := <-stream.Updates:
		if ok {
			t.Fatal("the subscriber channel should be closed, not delivering a frame")
		}
	case <-time.After(time.Second):
		t.Fatal("CloseStreams did not release the stream")
	}
	// A cancelled stream must not panic when the handler's deferred Cancel runs.
	stream.Cancel()
}

func TestFrameHubReadyCheckpointResumes(t *testing.T) {
	// stream.ready hands out the id of the frame just before the oldest retained
	// one. Reconnecting with it must resume rather than answer the client's own
	// checkpoint with event_cursor_expired.
	hub := newFrameHub("instance-1", "events", 2, time.Minute, 2)
	for i := 0; i < 3; i++ {
		hub.publish("runtime.updated", map[string]any{})
	}
	first, err := hub.open("", nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	checkpoint := first.Ready.ID
	first.Cancel()

	stream, err := hub.open(checkpoint, nil)
	if err != nil {
		t.Fatalf("reconnecting with the ready checkpoint failed: %v", err)
	}
	defer stream.Cancel()
	if len(stream.Replay) != 2 {
		t.Fatalf("replay = %d frames, want the 2 retained frames", len(stream.Replay))
	}
}

func TestFrameHubRefusesStreamsAfterClose(t *testing.T) {
	// Shutdown sweeps the hub. A handler admitted before the sweep must not
	// register a subscription afterwards, or it would outlive the process state
	// it reads from.
	hub := newFrameHub("instance-1", "events", 4, time.Minute, 4)
	hub.closeAll()
	if _, err := hub.open("", nil); err == nil {
		t.Fatal("a closed hub accepted a new stream")
	}
}

func TestFrameHubEmptyRingCheckpointIsResumable(t *testing.T) {
	hub := newFrameHub("instance-1", "events", 2, time.Minute, 2)
	hub.publish("runtime.updated", map[string]any{})
	// Simulate the last retained frame expiring: the sequence remains, but the
	// ring is empty.
	hub.mu.Lock()
	hub.start = 0
	hub.length = 0
	hub.mu.Unlock()

	stream, err := hub.open("", nil)
	if err != nil {
		t.Fatalf("open empty ring: %v", err)
	}
	checkpoint := stream.Ready.ID
	stream.Cancel()
	if checkpoint == hub.frameID(0) {
		t.Fatalf("empty ring checkpoint = %s, want the current sequence", checkpoint)
	}
	resumed, err := hub.open(checkpoint, nil)
	if err != nil {
		t.Fatalf("reconnecting with the empty-ring checkpoint failed: %v", err)
	}
	resumed.Cancel()
}

func TestFrameHubRejectsCursorFromDifferentFilterSet(t *testing.T) {
	hub := newFrameHub("instance-1", "logs", 4, time.Minute, 4)
	hub.publish("log", map[string]any{})
	stream, err := hub.openBound("", "level=info\x00target=daemon", nil)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := stream.Ready.ID
	stream.Cancel()
	if _, err := hub.openBound(checkpoint, "level=warn\x00target=daemon", nil); err == nil {
		t.Fatal("a cursor from another filter set was accepted")
	}
	resumed, err := hub.openBound(checkpoint, "level=info\x00target=daemon", nil)
	if err != nil {
		t.Fatalf("same-filter resume failed: %v", err)
	}
	resumed.Cancel()
}
