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
	cursor := encodePageCursor("instance-a", "dns_log", bind, "dl_7", now)
	after, err := decodePageCursor("instance-a", "dns_log", bind, cursor, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if after != "dl_7" {
		t.Fatalf("anchor = %q, want dl_7", after)
	}
}

func TestPageCursorRejectsForeignExpiredOrMalformed(t *testing.T) {
	now := time.Now()
	bind := pageCursorBind("example.com.", []string{"A"}, "", 100)
	cursor := encodePageCursor("instance-a", "dns_log", bind, "dl_7", now)

	cases := map[string]struct {
		instance, kind, bind, cursor string
		at                           time.Time
	}{
		"malformed":       {"instance-a", "dns_log", bind, "not-a-cursor", now},
		"other walk kind": {"instance-a", "flows", bind, cursor, now},
		"other instance":  {"instance-b", "dns_log", bind, cursor, now},
		"expired":         {"instance-a", "dns_log", bind, cursor, now.Add(pageCursorTTL + time.Second)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := decodePageCursor(tc.instance, tc.kind, tc.bind, tc.cursor, tc.at)
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

// A cursor this instance recognises but for another filter set or limit is 400,
// not 410: the client restarts the walk to change either.
func TestPageCursorRejectsChangedFiltersWithBadRequest(t *testing.T) {
	now := time.Now()
	bind := pageCursorBind("example.com.", []string{"A"}, "", 100)
	cursor := encodePageCursor("instance-a", "dns_log", bind, "dl_7", now)

	cases := map[string]string{
		"other filter": pageCursorBind("other.com.", []string{"A"}, "", 100),
		"other limit":  pageCursorBind("example.com.", []string{"A"}, "", 50),
	}
	for name, otherBind := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := decodePageCursor("instance-a", "dns_log", otherBind, cursor, now)
			apiErr, ok := err.(*nativeapi.APIError)
			if !ok || apiErr.Status != 400 || apiErr.Code != "invalid_request" {
				t.Fatalf("err = %v, want 400 invalid_request", err)
			}
		})
	}
}

func TestPageAfterResumesAfterTheAnchor(t *testing.T) {
	now := time.Now()
	bind := "bind"
	items := []string{"a", "b", "c", "d", "e"}
	key := func(item string) string { return item }

	page, next, err := pageAfterExpecting(items, key, "", "", "", 2, "instance-a", "flows", bind, now)
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(page) != 2 || page[0] != "a" || page[1] != "b" || next == nil {
		t.Fatalf("first page = %v next=%v", page, next)
	}
	anchor, err := decodePageCursor("instance-a", "flows", bind, *next, now)
	if err != nil || anchor != "b" {
		t.Fatalf("next anchor = %q err = %v", anchor, err)
	}
	page, _, err = pageAfterExpecting(items, key, anchor, "", "", 2, "instance-a", "flows", bind, now)
	if err != nil || len(page) != 2 || page[0] != "c" {
		t.Fatalf("second page = %v err=%v", page, err)
	}

	// The last page reports no cursor.
	page, last, err := pageAfterExpecting(items, key, "d", "", "", 2, "instance-a", "flows", bind, now)
	if err != nil || len(page) != 1 || page[0] != "e" || last != nil {
		t.Fatalf("last page = %v next=%v err=%v", page, last, err)
	}
}

func TestPageAfterIsStableWhenRecordsAppearAtTheHead(t *testing.T) {
	// The reviewer's failure mode: an offset window repeats or skips records when
	// the list grows at the head between pages. Resuming after a key must not.
	now := time.Now()
	bind := "bind"
	key := func(item string) string { return item }

	first := []string{"c", "b", "a"}
	page, next, err := pageAfterExpecting(first, key, "", "", "", 1, "instance-a", "flows", bind, now)
	if err != nil || len(page) != 1 || page[0] != "c" {
		t.Fatalf("first page = %v err=%v", page, err)
	}
	anchor, _ := decodePageCursor("instance-a", "flows", bind, *next, now)

	// A new record arrives at the head before the client asks for page two. With
	// an offset this page would repeat "c"; after a key it continues at "b".
	second := []string{"d", "c", "b", "a"}
	page, _, err = pageAfterExpecting(second, key, anchor, "", "", 1, "instance-a", "flows", bind, now)
	if err != nil || len(page) != 1 || page[0] != "b" {
		t.Fatalf("second page = %v err=%v, want [b]", page, err)
	}
}

func TestPageAfterRejectsAnEvictedAnchor(t *testing.T) {
	now := time.Now()
	// The anchor's record left the ring: the walk cannot continue on this
	// snapshot, so the caller reports 410 instead of skipping the gap.
	if _, _, err := pageAfterExpecting([]string{"y", "z"}, func(s string) string { return s }, "x", "", "", 2, "instance-a", "flows", "bind", now); err == nil {
		t.Fatal("an evicted anchor must expire the cursor")
	} else if apiErr, ok := err.(*nativeapi.APIError); !ok || apiErr.Status != 410 {
		t.Fatalf("err = %v, want 410 snapshot_expired", err)
	}
}

// A walk whose next record was evicted while the anchor survived must expire
// instead of silently skipping the gap.
func TestPageAfterExpectingDetectsEvictedNext(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := func(s string) string { return s }
	if _, _, err := pageAfterExpecting([]string{"c", "b", "a"}, key, "c", "b", "", 1, "i", "dns_log", "bind", now); err != nil {
		t.Fatalf("intact walk failed: %v", err)
	}
	if _, _, err := pageAfterExpecting([]string{"c", "a"}, key, "c", "b", "", 1, "i", "dns_log", "bind", now); err == nil {
		t.Fatal("evicted next record was not reported")
	}
}

func TestPageAfterExpectingDetectsEvictedTail(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := func(s string) string { return s }
	// The walk started when the oldest retained record was "a". If "a" has
	// been evicted while the anchor survived, a later page would silently omit
	// it even though expectNext still matches.
	if _, _, err := pageAfterExpecting([]string{"c", "b"}, key, "", "", "a", 1, "i", "dns_log", "bind", now); err == nil {
		t.Fatal("evicted tail was not reported")
	}
	if _, _, err := pageAfterExpecting([]string{"c", "b", "a"}, key, "", "", "a", 1, "i", "dns_log", "bind", now); err != nil {
		t.Fatalf("intact tail failed: %v", err)
	}
}
