/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "sync"

type udpConnStateTracker struct {
	mu      sync.Mutex
	entries map[bpfTuplesKey]*udpConnStateTrackerEntry
}

type udpConnStateTrackerEntry struct {
	refs     int
	deleting bool
	waiters  *sync.Cond
}

type udpConnStateTrackedRelease struct {
	key   bpfTuplesKey
	entry *udpConnStateTrackerEntry
}

func newUdpConnStateTracker() *udpConnStateTracker {
	return &udpConnStateTracker{
		entries: make(map[bpfTuplesKey]*udpConnStateTrackerEntry),
	}
}

func (t *udpConnStateTracker) Retain(keys []bpfTuplesKey) {
	if t == nil || len(keys) == 0 {
		return
	}
	for _, key := range keys {
		t.retain(key)
	}
}

func (t *udpConnStateTracker) retain(key bpfTuplesKey) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for {
		entry, ok := t.entries[key]
		if !ok {
			t.entries[key] = &udpConnStateTrackerEntry{refs: 1}
			return
		}
		if entry.deleting {
			if entry.waiters == nil {
				entry.waiters = sync.NewCond(&t.mu)
			}
			entry.waiters.Wait()
			continue
		}
		entry.refs++
		return
	}
}

func (t *udpConnStateTracker) BeginRelease(keys []bpfTuplesKey) []udpConnStateTrackedRelease {
	if t == nil || len(keys) == 0 {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	releases := make([]udpConnStateTrackedRelease, 0, len(keys))
	for _, key := range keys {
		entry, ok := t.entries[key]
		if !ok || entry.deleting {
			continue
		}
		switch {
		case entry.refs > 1:
			entry.refs--
		case entry.refs == 1:
			entry.refs = 0
			entry.deleting = true
			releases = append(releases, udpConnStateTrackedRelease{
				key:   key,
				entry: entry,
			})
		default:
			entry.refs = 0
		}
	}
	return releases
}

// Forget drops tracker ownership without deleting the underlying BPF tuples.
// Reload handoff uses this after the next generation has retained the same keys.
func (t *udpConnStateTracker) Forget(keys []bpfTuplesKey) {
	if t == nil || len(keys) == 0 {
		return
	}
	for _, key := range keys {
		t.forget(key)
	}
}

func (t *udpConnStateTracker) forget(key bpfTuplesKey) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for {
		entry, ok := t.entries[key]
		if !ok {
			return
		}
		if entry.deleting {
			if entry.waiters == nil {
				entry.waiters = sync.NewCond(&t.mu)
			}
			entry.waiters.Wait()
			continue
		}
		if entry.refs > 1 {
			entry.refs--
			return
		}
		delete(t.entries, key)
		if entry.waiters != nil {
			entry.waiters.Broadcast()
		}
		return
	}
}

func (t *udpConnStateTracker) FinalizeRelease(releases []udpConnStateTrackedRelease) {
	if t == nil || len(releases) == 0 {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for _, release := range releases {
		entry, ok := t.entries[release.key]
		if !ok || entry != release.entry {
			if release.entry.waiters != nil {
				release.entry.waiters.Broadcast()
			}
			continue
		}
		delete(t.entries, release.key)
		if entry.waiters != nil {
			entry.waiters.Broadcast()
		}
	}
}
