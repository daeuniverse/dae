/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

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
	ch    chan nativeapi.SSEFrame
	match func(event string, data any) bool
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
		id:    fmt.Sprintf("%s:%d", h.prefix, h.seq),
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
		case sub.ch <- nativeapi.SSEFrame{ID: frame.id, Event: event, Data: data}:
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

// open builds a resumable stream. An unknown or expired cursor reports
// event_cursor_expired, as the contract requires.
func (h *frameHub) open(lastEventID string, match func(event string, data any) bool) (*nativeapi.SSEStream, error) {
	if h == nil {
		return nil, nativeapi.NewAPIError(503, "temporarily_unavailable", "event stream is unavailable")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	h.pruneLocked(now)

	if h.maxClients > 0 && len(h.subs) >= h.maxClients {
		return nil, nativeapi.NewAPIError(503, "temporarily_unavailable", "too many open event streams")
	}

	readySeq := uint64(0)
	if lastEventID != "" {
		cursor, ok := h.frameByIDLocked(lastEventID)
		switch {
		case ok:
			readySeq = cursor.seq
		case lastEventID == fmt.Sprintf("%s:0", h.prefix):
			// The client attached before any record existed; resume from the
			// retained frames instead of rejecting the cursor.
			if h.length > 0 {
				readySeq = h.frames[h.start].seq - 1
			}
		default:
			return nil, nativeapi.NewAPIError(409, "event_cursor_expired", "event cursor is unknown or expired")
		}
	} else if h.length > 0 {
		readySeq = h.frames[h.start].seq - 1
	}

	ready := nativeapi.SSEFrame{
		ID:    fmt.Sprintf("%s:%d", h.prefix, readySeq),
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
		replay = append(replay, nativeapi.SSEFrame{ID: frame.id, Event: frame.event, Data: frame.data})
	}

	id := h.nextSub
	h.nextSub++
	sub := &frameSubscriber{ch: make(chan nativeapi.SSEFrame, 256), match: match}
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
	return p.logHub.open(lastEventID, match)
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
	return p.eventHub.open(lastEventID, match)
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
