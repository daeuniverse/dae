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

type pageCursor struct {
	Kind      string `json:"k"`
	Bind      string `json:"b"`
	Offset    int    `json:"o"`
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
		case bool:
			values = append(values, strconv.FormatBool(typed))
		case []string:
			values = append(values, strings.Join(typed, ","))
		}
	}
	return strings.Join(values, "\x00")
}

func encodePageCursor(kind, bind string, offset int, now time.Time) string {
	payload, err := json.Marshal(pageCursor{
		Kind:      kind,
		Bind:      bind,
		Offset:    offset,
		ExpiresAt: now.Add(pageCursorTTL).Unix(),
	})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

// decodePageCursor resolves an opaque cursor for one page walk. A cursor issued
// by another walk (different filters or limit), an expired one, or a malformed
// one reports 410 snapshot_expired so the client restarts without a cursor.
func decodePageCursor(kind, bind, value string, now time.Time) (int, error) {
	expired := nativeapi.NewAPIError(410, "snapshot_expired", "the page snapshot expired; restart the page walk")
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return 0, expired
	}
	var cursor pageCursor
	if err := json.Unmarshal(raw, &cursor); err != nil {
		return 0, expired
	}
	if cursor.Kind != kind || cursor.Bind != bind || cursor.Offset < 0 || cursor.ExpiresAt < now.Unix() {
		return 0, expired
	}
	return cursor.Offset, nil
}

// pageOf clamps one page window and reports the cursor for the next page.
func pageOf(total, offset, limit int, kind, bind string, now time.Time) (start, end int, next *string) {
	if offset > total {
		offset = total
	}
	end = offset + limit
	if end > total {
		end = total
	}
	if end < total {
		value := encodePageCursor(kind, bind, end, now)
		next = &value
	}
	return offset, end, next
}
