/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// These tests pin the log contract of a failed DNS response cache store. The
// store is a latency optimization: the response is already on its way to the
// client, so a failure is not an outage. It must not be reported once per
// query at warning level from one call site while the identical failure from
// another call site is debug-only; every site shares one pace and one count.

func newCacheStoreTestController(level logrus.Level) (*DnsController, *syncLogBuffer) {
	logger, out := newLogCapture(level)
	return &DnsController{
		dnsControllerStore: newDnsControllerStore(),
		log:                logger,
	}, out
}

func countLogLevel(lines []string, level string) int {
	n := 0
	for _, line := range lines {
		if strings.Contains(line, "level="+level) {
			n++
		}
	}
	return n
}

// TestDnsCacheStoreFailureIsOnePacedWarningForEveryCallSite is the
// duplicate-report regression: the sync writer path used to warn per query
// while the async path logged the same failure at debug, so one condition was
// reported twice per query and with two different levels.
func TestDnsCacheStoreFailureIsOnePacedWarningForEveryCallSite(t *testing.T) {
	c, out := newCacheStoreTestController(logrus.WarnLevel)
	storeErr := stderrors.New("cache entry has no packable question")

	c.noteDnsCacheStoreFailure("response writer", storeErr)
	c.noteDnsCacheStoreFailure("async after send", storeErr)
	c.noteDnsCacheStoreFailure("controller response", storeErr)

	lines := out.lines()
	if got := countLogLevel(lines, "warning"); got != 1 {
		t.Fatalf("warning lines = %d, want 1 for one condition: %v", got, lines)
	}
	if got := c.dnsCacheStoreFailureAlert.observations.Load(); got != 3 {
		t.Fatalf("failed stores = %d, want 3: a paced report must still count every failure", got)
	}

	// The paced line names the call site it reports, so an operator can tell
	// the sync writer apart from the async path without one line per query.
	if !strings.Contains(lines[0], "response writer") {
		t.Fatalf("paced line %q does not name its call site", lines[0])
	}

	rewindPace(&c.dnsCacheStoreFailureAlert, time.Now(), dnsCacheStoreFailureLogInterval)
	c.noteDnsCacheStoreFailure("async after send", storeErr)
	lines = out.lines()
	if got := countLogLevel(lines, "warning"); got != 2 {
		t.Fatalf("warning lines after the pace = %d, want 2: %v", got, lines)
	}
	if !strings.Contains(lines[len(lines)-1], "failures=4") {
		t.Fatalf("paced line %q does not carry the accumulated failure count", lines[len(lines)-1])
	}
}

// TestDnsCacheStoreFailureKeepsPerQueryDetailAtDebug guards against the paced
// warning becoming a silent drop: the per-query detail (which query, which
// error) stays available at debug, which is the level meant for per-query
// decisions.
func TestDnsCacheStoreFailureKeepsPerQueryDetailAtDebug(t *testing.T) {
	c, out := newCacheStoreTestController(logrus.DebugLevel)
	storeErr := stderrors.New("cache entry has no packable question")

	for range 3 {
		c.noteDnsCacheStoreFailure("response writer", storeErr)
	}

	lines := out.lines()
	if got := countLogLevel(lines, "debug"); got != 3 {
		t.Fatalf("debug lines = %d, want one per failed store: %v", got, lines)
	}
	if got := countLogLevel(lines, "warning"); got != 1 {
		t.Fatalf("warning lines = %d, want 1: %v", got, lines)
	}
}

// TestDnsCacheStoreFailureIgnoresNilErrorAndUnusableController keeps the
// reporter safe on the paths that call it without a store or without a
// failure, including the reload facades that share the store.
func TestDnsCacheStoreFailureIgnoresNilErrorAndUnusableController(t *testing.T) {
	c, out := newCacheStoreTestController(logrus.DebugLevel)
	if c.dnsControllerStore == nil {
		t.Fatal("test controller must carry the shared store")
	}
	c.noteDnsCacheStoreFailure("response writer", nil)

	var nilController *DnsController
	nilController.noteDnsCacheStoreFailure("response writer", stderrors.New("boom"))

	if lines := out.lines(); len(lines) != 0 {
		t.Fatalf("no line expected, got %v", lines)
	}

	facade := c.sharedStoreFacade()
	facade.noteDnsCacheStoreFailure("async after send", stderrors.New("boom"))
	if got := c.dnsCacheStoreFailureAlert.observations.Load(); got != 1 {
		t.Fatalf("a reload facade must share the owner's pace and count, got %d observations", got)
	}
}
