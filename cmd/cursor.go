/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
)

// pageCursorTTL bounds how long an issued cursor stays valid. The contract
// expects an unrecognised or expired cursor to fail with 410 snapshot_expired.
const pageCursorTTL = 5 * time.Minute

// pageCursor carries the key of the last item a client received, not an offset
// into the live list. An offset is only valid against the snapshot it was
// computed from; these lists grow at the head while a client walks them, so an
// offset window repeats or skips records. Continuing after a key is stable as
// long as that record is still retained.
type pageCursor struct {
	Kind      string `json:"k"`
	Instance  string `json:"i"`
	Bind      string `json:"b"`
	After     string `json:"a"`
	Next      string `json:"n,omitempty"`
	Oldest    string `json:"o,omitempty"`
	ExpiresAt int64  `json:"e"`
}

func pageCursorBind(parts ...any) string {
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		switch typed := part.(type) {
		case string:
			values = append(values, typed)
		case int:
			values = append(values, strconv.Itoa(typed))
		case uint64:
			values = append(values, strconv.FormatUint(typed, 10))
		case bool:
			values = append(values, strconv.FormatBool(typed))
		case []string:
			values = append(values, strings.Join(typed, ","))
		}
	}
	return strings.Join(values, "\x00")
}

func encodePageCursor(instance, kind, bind, after string, now time.Time) string {
	return encodePageCursorNext(instance, kind, bind, after, "", "", now)
}

// encodePageCursorNext also records the key of the first record of the next
// page, which lets a ring-backed walk notice that records were evicted between
// the two pages.
func encodePageCursorNext(instance, kind, bind, after, next, oldest string, now time.Time) string {
	payload, err := json.Marshal(pageCursor{
		Next:      next,
		Oldest:    oldest,
		Kind:      kind,
		Instance:  instance,
		Bind:      bind,
		After:     after,
		ExpiresAt: now.Add(pageCursorTTL).Unix(),
	})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

// decodePageCursor resolves an opaque cursor for one page walk. A cursor that
// names another process, another walk, or an expired snapshot reports 410
// snapshot_expired, which is the contract's "the server no longer recognises
// it". A cursor from this instance and endpoint but another filter set or limit
// is recognised and reports 400 invalid_request instead; the client has to
// restart the walk to change either.
func decodePageCursor(instance, kind, bind, value string, now time.Time) (string, error) {
	after, _, _, err := decodePageCursorNext(instance, kind, bind, value, now)
	return after, err
}

func decodePageCursorNext(instance, kind, bind, value string, now time.Time) (string, string, string, error) {
	expired := nativeapi.NewAPIError(410, "snapshot_expired", "the page snapshot expired; restart the page walk")
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", "", "", expired
	}
	var cursor pageCursor
	if err := json.Unmarshal(raw, &cursor); err != nil {
		return "", "", "", expired
	}
	if cursor.Kind != kind || cursor.Instance != instance || cursor.After == "" || cursor.ExpiresAt < now.Unix() {
		return "", "", "", expired
	}
	if cursor.Bind != bind {
		return "", "", "", nativeapi.NewAPIError(400, "invalid_request", "the cursor was issued for different filters or a different limit; restart the page walk")
	}
	return cursor.After, cursor.Next, cursor.Oldest, nil
}

// pageAfterExpecting returns the items that follow the anchor in a stable,
// ordered list.
//
// The anchor is the key of the last item the client received. Every list this
// engine paginates is ordered and grows at the head, so resuming after a key
// keeps a walk consistent while records are added at the front, which an offset
// window cannot: a new head shifts every later page by one. An anchor that is no
// longer present means the walk cannot be continued on this snapshot - the
// record was evicted - so the caller reports 410 rather than silently skipping
// the gap.
//
// expectNext is the key the previous page promised would come next; if the
// anchor survives but that record does not, records were evicted in between and
// the walk would silently skip them, so it reports 410 like a lost anchor.
// oldestKey is for a ring-backed list, which evicts from the oldest end.
func pageAfterExpecting[T any](items []T, keyOf func(T) string, after, expectNext, oldestKey string, limit int, instance, kind, bind string, now time.Time) ([]T, *string, error) {
	if oldestKey != "" {
		// A ring-backed list evicts from the oldest end. The immediate
		// successor check only catches a gap at the page boundary; if the
		// eviction removes an unread record further down, the oldest key moves
		// and continuing would silently omit it.
		if len(items) == 0 || keyOf(items[len(items)-1]) != oldestKey {
			return nil, nil, nativeapi.NewAPIError(410, "snapshot_expired", "the page snapshot expired; restart the page walk")
		}
	}
	start := 0
	if after != "" {
		found := false
		for i, item := range items {
			if keyOf(item) == after {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return nil, nil, nativeapi.NewAPIError(410, "snapshot_expired", "the page snapshot expired; restart the page walk")
		}
	}
	if start > len(items) {
		start = len(items)
	}
	if expectNext != "" && (start >= len(items) || keyOf(items[start]) != expectNext) {
		return nil, nil, nativeapi.NewAPIError(410, "snapshot_expired", "the page snapshot expired; restart the page walk")
	}
	end := start + limit
	if end > len(items) {
		end = len(items)
	}
	var next *string
	if end < len(items) && end > start {
		oldest := ""
		if len(items) > 0 {
			oldest = keyOf(items[len(items)-1])
		}
		value := encodePageCursorNext(instance, kind, bind, keyOf(items[end-1]), keyOf(items[end]), oldest, now)
		next = &value
	}
	return items[start:end], next, nil
}
