/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/sirupsen/logrus"
)

type storedFrame struct {
	seq   uint64
	id    string
	event string
	data  any
	at    time.Time
}

type frameSubscriber struct {
	ch      chan nativeapi.SSEFrame
	match   func(event string, data any) bool
	bindTag string
}

// frameHub is a bounded, resumable SSE ring shared by logs and events.
type frameHub struct {
	mu         sync.Mutex
	instanceID string
	prefix     string
	capacity   int
	retention  time.Duration
	maxClients int
	seq        uint64
	frames     []storedFrame
	start      int
	length     int
	subs       map[int]*frameSubscriber
	nextSub    int
	// closed records that shutdown swept the hub. A handler admitted before the
	// sweep but registering after it must not resurrect a subscription the
	// process no longer serves.
	closed bool
}

func newFrameHub(instanceID, prefix string, capacity int, retention time.Duration, maxClients int) *frameHub {
	if capacity <= 0 {
		capacity = 1
	}
	if retention <= 0 {
		retention = time.Minute
	}
	return &frameHub{
		instanceID: instanceID,
		prefix:     prefix,
		capacity:   capacity,
		retention:  retention,
		maxClients: maxClients,
		frames:     make([]storedFrame, capacity),
		subs:       make(map[int]*frameSubscriber),
	}
}

func (h *frameHub) publish(event string, data any) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneLocked(time.Now())
	h.seq++
	frame := storedFrame{
		seq:   h.seq,
		id:    h.frameID(h.seq),
		event: event,
		data:  data,
		at:    time.Now(),
	}
	if h.length < len(h.frames) {
		index := (h.start + h.length) % len(h.frames)
		h.frames[index] = frame
		h.length++
	} else {
		h.frames[h.start] = frame
		h.start = (h.start + 1) % len(h.frames)
	}
	for id, sub := range h.subs {
		if sub.match != nil && !sub.match(event, data) {
			continue
		}
		select {
		case sub.ch <- nativeapi.SSEFrame{ID: boundSSEFrameID(frame.id, sub.bindTag), Event: event, Data: data}:
		default:
			// Slow client: close its stream instead of blocking the publisher.
			close(sub.ch)
			delete(h.subs, id)
		}
	}
}

func (h *frameHub) pruneLocked(now time.Time) {
	cutoff := now.Add(-h.retention)
	for h.length > 0 {
		oldest := h.frames[h.start]
		if !oldest.at.Before(cutoff) {
			break
		}
		h.start = (h.start + 1) % len(h.frames)
		h.length--
	}
}

func (h *frameHub) frameByIDLocked(id string) (storedFrame, bool) {
	for i := 0; i < h.length; i++ {
		frame := h.frames[(h.start+i)%len(h.frames)]
		if frame.id == id {
			return frame, true
		}
	}
	return storedFrame{}, false
}

// closeAll ends every open stream. A shutdown otherwise waits for each SSE
// handler, which only returns when its context is cancelled or a frame arrives,
// so an idle stream held the listener open for the whole shutdown grace period.
func (h *frameHub) closeAll() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for id, sub := range h.subs {
		close(sub.ch)
		delete(h.subs, id)
	}
}

// CloseStreams releases the open SSE streams so shutdown does not wait for
// clients that keep an idle connection open.
func (p *nativeAPIProvider) CloseStreams() {
	if p == nil {
		return
	}
	p.logHub.closeAll()
	p.eventHub.closeAll()
}

// frameID names one frame. The instance is part of the ID so a cursor issued by
// a previous process is rejected with event_cursor_expired instead of being
// accepted against a fresh ring that happens to share the sequence numbers.
func (h *frameHub) frameID(seq uint64) string {
	return fmt.Sprintf("%s:%s:%d", h.instanceID, h.prefix, seq)
}

// sseBindTag is a short, stable fingerprint of the normalized filter set.
func sseBindTag(bind string) string {
	if bind == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(bind))
	return hex.EncodeToString(sum[:4])
}

func boundSSEFrameID(id, tag string) string {
	if tag == "" {
		return id
	}
	return id + "@" + tag
}

func splitSSECursor(id string) (string, string) {
	if index := strings.LastIndexByte(id, '@'); index >= 0 {
		return id[:index], id[index+1:]
	}
	return id, ""
}

// open builds a resumable stream. An unknown or expired cursor reports
// event_cursor_expired, as the contract requires.
func (h *frameHub) open(lastEventID string, match func(event string, data any) bool) (*nativeapi.SSEStream, error) {
	return h.openBound(lastEventID, "", match)
}

// openBound binds the resumable cursor to one normalized filter set. The tag
// is appended to every frame id this subscription sees, so a client that
// changes level/target and reconnects with the old id is rejected instead of
// receiving an empty replay that silently skips earlier matching records.
func (h *frameHub) openBound(lastEventID, bind string, match func(event string, data any) bool) (*nativeapi.SSEStream, error) {
	if h == nil {
		return nil, nativeapi.NewAPIError(503, "temporarily_unavailable", "event stream is unavailable")
	}
	bindTag := sseBindTag(bind)
	cursorID, cursorTag := splitSSECursor(lastEventID)
	if cursorTag != "" && cursorTag != bindTag {
		return nil, nativeapi.NewAPIError(409, "event_cursor_expired", "event cursor was issued for a different filter set")
	}
	lastEventID = cursorID
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, nativeapi.NewAPIError(503, "temporarily_unavailable", "the event stream is shutting down")
	}
	now := time.Now()
	h.pruneLocked(now)

	if h.maxClients > 0 && len(h.subs) >= h.maxClients {
		return nil, nativeapi.NewAPIError(503, "temporarily_unavailable", "too many open event streams")
	}

	readySeq := uint64(0)
	switch {
	case lastEventID != "":
		if cursor, ok := h.frameByIDLocked(lastEventID); ok {
			readySeq = cursor.seq
		} else {
			// The id may name the frame immediately before the oldest retained
			// one: that is the checkpoint stream.ready hands out, and resuming
			// there loses nothing. Any other unknown id means records were
			// evicted, so the client has to resync.
			oldestSeq := uint64(0)
			if h.length > 0 {
				oldestSeq = h.frames[h.start].seq
			}
			boundary := uint64(0)
			if oldestSeq > 0 {
				boundary = oldestSeq - 1
			}
			switch {
			case h.seq == 0 && lastEventID == h.frameID(0):
				readySeq = 0
			case h.length == 0 && h.seq > 0 && lastEventID == h.frameID(h.seq):
				// The ring is empty but records existed. The checkpoint this
				// server just handed out names the current sequence, not zero;
				// accepting it keeps a reconnect from failing as expired.
				readySeq = h.seq
			case h.length > 0 && lastEventID == h.frameID(boundary):
				readySeq = boundary
			default:
				return nil, nativeapi.NewAPIError(409, "event_cursor_expired", "event cursor is unknown or expired")
			}
		}
	case h.length > 0:
		readySeq = h.frames[h.start].seq - 1
	default:
		// An empty ring still has a sequence: a new stream must checkpoint at
		// that sequence, or reconnect would replay an id the hub rejects.
		readySeq = h.seq
	}

	ready := nativeapi.SSEFrame{
		ID:    boundSSEFrameID(h.frameID(readySeq), bindTag),
		Event: "stream.ready",
		Data: nativeapi.StreamReadyEvent{
			InstanceID: h.instanceID,
			ObservedAt: now.UTC().Format(time.RFC3339),
		},
	}
	replay := make([]nativeapi.SSEFrame, 0, h.length)
	for i := 0; i < h.length; i++ {
		frame := h.frames[(h.start+i)%len(h.frames)]
		if frame.seq <= readySeq {
			continue
		}
		if match != nil && !match(frame.event, frame.data) {
			continue
		}
		replay = append(replay, nativeapi.SSEFrame{ID: boundSSEFrameID(frame.id, bindTag), Event: frame.event, Data: frame.data})
	}

	id := h.nextSub
	h.nextSub++
	sub := &frameSubscriber{ch: make(chan nativeapi.SSEFrame, 256), match: match, bindTag: bindTag}
	h.subs[id] = sub
	cancel := func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if existing, ok := h.subs[id]; ok {
			delete(h.subs, id)
			close(existing.ch)
		}
	}
	return &nativeapi.SSEStream{Ready: ready, Replay: replay, Updates: sub.ch, Cancel: cancel}, nil
}

var logLevelRank = map[string]int{
	"trace": 0,
	"debug": 1,
	"info":  2,
	"warn":  3,
	"error": 4,
}

func logLevelName(level logrus.Level) string {
	switch level {
	case logrus.TraceLevel:
		return "trace"
	case logrus.DebugLevel:
		return "debug"
	case logrus.InfoLevel:
		return "info"
	case logrus.WarnLevel:
		return "warn"
	default:
		return "error"
	}
}

var (
	bearerPattern = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]+`)
	queryPattern  = regexp.MustCompile(`\?[^\s"]+`)
)

func sanitizeLogMessage(message string) string {
	message = bearerPattern.ReplaceAllString(message, "Bearer [redacted]")
	message = queryPattern.ReplaceAllString(message, "?[redacted]")
	// A subscription or share link carries its credential in the userinfo, which
	// is neither a bearer token nor a query parameter: scheme://user:pass@host.
	message = common.RedactInlineURLs(message)
	return message
}

func sanitizeLogFields(fields logrus.Fields) map[string]any {
	if len(fields) == 0 {
		return nil
	}
	result := make(map[string]any, len(fields))
	for key, value := range fields {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "secret") || strings.Contains(lower, "token") ||
			strings.Contains(lower, "authorization") || strings.Contains(lower, "password") ||
			strings.Contains(lower, "cookie") {
			continue
		}
		switch typed := value.(type) {
		case error:
			result[key] = sanitizeLogMessage(typed.Error())
		case string:
			result[key] = sanitizeLogMessage(typed)
		case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, nil:
			result[key] = typed
		default:
			result[key] = sanitizeLogMessage(fmt.Sprint(typed))
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

type logHubHook struct {
	hub *frameHub
}

func (h *logHubHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *logHubHook) Fire(entry *logrus.Entry) error {
	if h == nil || h.hub == nil {
		return nil
	}
	record := nativeapi.LogRecord{
		TS:      entry.Time.UTC().Format(time.RFC3339Nano),
		Level:   logLevelName(entry.Level),
		Message: sanitizeLogMessage(entry.Message),
		Fields:  sanitizeLogFields(entry.Data),
	}
	if target, ok := entry.Data["target"].(string); ok && target != "" {
		record.Target = &target
	}
	h.hub.publish("log", record)
	return nil
}

// LogLevels lists the levels the log stream can filter on.
func (p *nativeAPIProvider) LogLevels() []string {
	return []string{"trace", "debug", "info", "warn", "error"}
}

// LogFilters lists the supported log query filters.
func (p *nativeAPIProvider) LogFilters() []string {
	return []string{"level", "target"}
}

// OpenLogStream opens a resumable log stream.
func (p *nativeAPIProvider) OpenLogStream(ctx context.Context, level, target, lastEventID string) (*nativeapi.SSEStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.logHub == nil {
		return nil, nativeapi.NewAPIError(503, "temporarily_unavailable", "log capture is unavailable")
	}
	minRank := -1
	if level != "" {
		minRank = logLevelRank[level]
	}
	match := func(_ string, data any) bool {
		record, ok := data.(nativeapi.LogRecord)
		if !ok {
			return false
		}
		if minRank >= 0 && logLevelRank[record.Level] < minRank {
			return false
		}
		if target != "" {
			if record.Target == nil || !strings.HasPrefix(*record.Target, target) {
				return false
			}
		}
		return true
	}
	return p.logHub.openBound(lastEventID, "log\x00"+level+"\x00"+target, match)
}

// EventKinds lists the invalidation events this engine publishes.
func (p *nativeAPIProvider) EventKinds() []string {
	return []string{"stream.ready", "runtime.updated", "operation.updated", "generation.changed"}
}

// OpenEventStream opens a resumable invalidation event stream.
func (p *nativeAPIProvider) OpenEventStream(ctx context.Context, kinds []string, flowID, lastEventID string) (*nativeapi.SSEStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.eventHub == nil {
		return nil, nativeapi.NewAPIError(503, "temporarily_unavailable", "event capture is unavailable")
	}
	allowed := make(map[string]struct{}, len(kinds))
	for _, kind := range kinds {
		allowed[kind] = struct{}{}
	}
	match := func(event string, data any) bool {
		if len(allowed) == 0 {
			return true
		}
		_, ok := allowed[event]
		return ok
	}
	return p.eventHub.openBound(lastEventID, "event\x00"+strings.Join(kinds, ",")+"\x00"+flowID, match)
}

func (p *nativeAPIProvider) publishRuntimeUpdated() {
	if p == nil || p.eventHub == nil {
		return
	}
	p.eventHub.publish("runtime.updated", map[string]any{
		"instance_id": p.status.snapshot().InstanceID,
		"observed_at": time.Now().UTC().Format(time.RFC3339),
		"href":        "/api/v1/runtime",
	})
}

func (p *nativeAPIProvider) publishOperationUpdated(operationID, status string) {
	if p == nil || p.eventHub == nil || operationID == "" {
		return
	}
	p.eventHub.publish("operation.updated", map[string]any{
		"instance_id": p.status.snapshot().InstanceID,
		"observed_at": time.Now().UTC().Format(time.RFC3339),
		"resource_id": operationID,
		"status":      status,
		"href":        "/api/v1/operations/" + operationID,
	})
}

func (p *nativeAPIProvider) publishGenerationChanged(previous, current string) {
	if p == nil || p.eventHub == nil || current == "" {
		return
	}
	if previous == "" {
		previous = current
	}
	p.eventHub.publish("generation.changed", map[string]any{
		"instance_id":            p.status.snapshot().InstanceID,
		"observed_at":            time.Now().UTC().Format(time.RFC3339),
		"previous_generation_id": previous,
		"generation_id":          current,
	})
}

var (
	_ nativeapi.LogProvider   = (*nativeAPIProvider)(nil)
	_ nativeapi.EventProvider = (*nativeAPIProvider)(nil)
)
