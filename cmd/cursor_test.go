/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
)

func TestPageCursorRoundTrip(t *testing.T) {
	now := time.Now()
	bind := pageCursorBind("example.com.", []string{"A"}, "10.0.0.1", 100)
	cursor := encodePageCursor("dns_log", bind, 7, now)
	offset, err := decodePageCursor("dns_log", bind, cursor, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if offset != 7 {
		t.Fatalf("offset = %d, want 7", offset)
	}
}

func TestPageCursorRejectsForeignExpiredOrMalformed(t *testing.T) {
	now := time.Now()
	bind := pageCursorBind("example.com.", []string{"A"}, "", 100)
	cursor := encodePageCursor("dns_log", bind, 7, now)

	cases := map[string]struct {
		kind, bind, cursor string
		at                 time.Time
	}{
		"malformed":       {"dns_log", bind, "not-a-cursor", now},
		"other walk kind": {"flows", bind, cursor, now},
		"other filter":    {"dns_log", pageCursorBind("other.com.", []string{"A"}, "", 100), cursor, now},
		"other limit":     {"dns_log", pageCursorBind("example.com.", []string{"A"}, "", 50), cursor, now},
		"expired":         {"dns_log", bind, cursor, now.Add(pageCursorTTL + time.Second)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := decodePageCursor(tc.kind, tc.bind, tc.cursor, tc.at)
			apiErr, ok := err.(*nativeapi.APIError)
			if !ok {
				t.Fatalf("err = %v, want *nativeapi.APIError", err)
			}
			if apiErr.Status != 410 || apiErr.Code != "snapshot_expired" {
				t.Fatalf("error = %+v, want 410 snapshot_expired", apiErr)
			}
		})
	}
}

func TestPageOfMarksLastPage(t *testing.T) {
	now := time.Now()
	bind := "bind"
	start, end, next := pageOf(5, 0, 2, "flows", bind, now)
	if start != 0 || end != 2 || next == nil {
		t.Fatalf("first page = %d..%d next=%v", start, end, next)
	}
	offset, err := decodePageCursor("flows", bind, *next, now)
	if err != nil || offset != 2 {
		t.Fatalf("next cursor offset = %d err = %v", offset, err)
	}
	if _, _, next = pageOf(5, 4, 2, "flows", bind, now); next != nil {
		t.Fatalf("last page must not issue a cursor, got %q", *next)
	}
	if start, end, _ = pageOf(5, 9, 2, "flows", bind, now); start != 5 || end != 5 {
		t.Fatalf("out-of-range offset = %d..%d, want empty tail page", start, end)
	}
}
