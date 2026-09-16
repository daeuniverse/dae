/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"io"
	"testing"
)

type countingCloser struct{ closes *int }

func (c countingCloser) Close() error { *c.closes++; return nil }

var _ io.Closer = countingCloser{}

// Reload semantics: a second attach for the same bpfObjects (fresh
// controlPlaneCore, handed-over objects) must reuse the links instead of
// re-attaching, and the links must survive until the last generation
// releases them.
func TestTCPOffloadLinksReuseAcrossGenerations(t *testing.T) {
	bpf := &bpfObjects{}
	var verdictCloses, accountCloses int
	attachCalls := 0
	attach := func() (tcpOffloadLinks, error) {
		attachCalls++
		return tcpOffloadLinks{
			verdict: countingCloser{&verdictCloses},
			account: countingCloser{&accountCloses},
		}, nil
	}

	// First generation attaches.
	reused, err := attachTCPOffloadLinks(bpf, attach)
	if err != nil {
		t.Fatalf("first attach: %v", err)
	}
	if reused {
		t.Fatal("first attach must not report reuse")
	}
	// Second generation (reload) reuses without re-attaching.
	reused, err = attachTCPOffloadLinks(bpf, attach)
	if err != nil {
		t.Fatalf("second attach: %v", err)
	}
	if !reused {
		t.Fatal("second attach for the same bpfObjects must reuse")
	}
	if attachCalls != 1 {
		t.Fatalf("attach callback ran %d times, want 1", attachCalls)
	}

	// Old generation finalizes: links must stay alive for the new one.
	releaseTCPOffloadLinks(bpf)
	if verdictCloses != 0 || accountCloses != 0 {
		t.Fatalf("links closed while a generation still holds them: verdict=%d account=%d", verdictCloses, accountCloses)
	}
	// Last generation releases: both links close exactly once.
	releaseTCPOffloadLinks(bpf)
	if verdictCloses != 1 || accountCloses != 1 {
		t.Fatalf("links closed verdict=%d account=%d, want 1/1", verdictCloses, accountCloses)
	}

	// Registry is empty again: a fresh attach is possible (e.g. after the
	// objects are finally closed and a new set is loaded).
	reused, err = attachTCPOffloadLinks(bpf, attach)
	if err != nil {
		t.Fatalf("attach after full release: %v", err)
	}
	if reused || attachCalls != 2 {
		t.Fatalf("after full release attachCalls=%d reused=%v, want 2/false", attachCalls, reused)
	}
	releaseTCPOffloadLinks(bpf)
	if verdictCloses != 2 {
		t.Fatalf("second lifecycle closed verdict=%d, want 2", verdictCloses)
	}
}

// A failed attach (e.g. EBUSY from a foreign program) must leave nothing
// registered so a later retry starts clean.
func TestTCPOffloadLinksFailedAttachNotRegistered(t *testing.T) {
	bpf := &bpfObjects{}
	_, err := attachTCPOffloadLinks(bpf, func() (tcpOffloadLinks, error) {
		return tcpOffloadLinks{}, errors.New("attach rejected")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	releaseTCPOffloadLinks(bpf) // must be a no-op, not a panic

	tcpOffloadLinkMu.Lock()
	_, registered := tcpOffloadLinkRegistry[bpf]
	tcpOffloadLinkMu.Unlock()
	if registered {
		t.Fatal("failed attach must not register links")
	}
}

// A nil accounting link (DAE_FUSE_ACCOUNT=0) must not trip the release path.
func TestTCPOffloadLinksNilAccountClose(t *testing.T) {
	bpf := &bpfObjects{}
	var closes int
	_, err := attachTCPOffloadLinks(bpf, func() (tcpOffloadLinks, error) {
		return tcpOffloadLinks{verdict: countingCloser{&closes}}, nil
	})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	releaseTCPOffloadLinks(bpf)
	if closes != 1 {
		t.Fatalf("verdict closed %d times, want 1", closes)
	}
}
