/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"time"

	dnsmessage "github.com/miekg/dns"
)

const (
	// PreferenceResolutionDelay is the time to wait for a preferred
	// DNS response type (e.g., AAAA) after receiving a non-preferred
	// type (e.g., A). Based on RFC 8305 Happy Eyeballs Resolution Delay.
	//
	// From RFC 8305 Section 3:
	// "If a positive A response is received first due to reordering,
	// the client SHOULD wait a short time for the AAAA response to
	// ensure that preference is given to IPv6 (it is common for the
	// AAAA response to follow the A response by a few milliseconds).
	// The recommended value for the Resolution Delay is 50 milliseconds."
	PreferenceResolutionDelay = 50 * time.Millisecond
)

// preferenceWait represents a request waiting for its preferred DNS response type.
// When a non-preferred response arrives (e.g., A when prefer=6), we wait briefly
// to see if the preferred response (e.g., AAAA) arrives before responding.
type preferenceWait struct {
	qname string // Key this wait is registered under (identity for removal)
	qtype uint16 // Original query type (A or AAAA)
	// preferred records whether the preferred response arrived in time;
	// preferredHasRecords additionally records whether that response carried
	// address records of the preferred family. Only a preferred family that
	// really has records may suppress the non-preferred answer, so the two
	// conditions are tracked separately.
	preferred           bool
	preferredHasRecords bool
	done                chan struct{} // Closed when wait is complete (timeout or preferred arrived)
	deadline            time.Time     // Wait deadline
}

// preferenceWaitRegistry manages concurrent DNS queries waiting for preferred response types.
// Thread-safe for concurrent access.
type preferenceWaitRegistry struct {
	mu    sync.RWMutex
	waits map[string]*preferenceWait // key: qname → wait info
}

// newPreferenceWaitRegistry creates a new registry.
func newPreferenceWaitRegistry() *preferenceWaitRegistry {
	return &preferenceWaitRegistry{
		waits: make(map[string]*preferenceWait),
	}
}

// registerWait registers a wait for the preferred response type.
// Returns the wait struct if registered, nil if qtypePrefer is disabled.
// If a wait already exists for this qname, returns the existing wait.
func (r *preferenceWaitRegistry) registerWait(qname string, qtype uint16, qtypePrefer uint16) *preferenceWait {
	// Fast path: preference not enabled
	if qtypePrefer == 0 {
		return nil
	}

	// Only wait for A/AAAA responses
	if qtype != dnsmessage.TypeA && qtype != dnsmessage.TypeAAAA {
		return nil
	}

	// No wait needed if this is the preferred type
	if qtype == qtypePrefer {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if already waiting
	if existing, ok := r.waits[qname]; ok {
		return existing
	}

	// Create new wait
	w := &preferenceWait{
		qname:    qname,
		qtype:    qtype,
		done:     make(chan struct{}),
		deadline: time.Now().Add(PreferenceResolutionDelay),
	}
	r.waits[qname] = w
	return w
}

// notifyPreferred notifies a waiting query that the preferred response has arrived.
// hasRecords tells whether that response carried records of the preferred family.
// Returns true if a waiter was found and notified.
func (r *preferenceWaitRegistry) notifyPreferred(qname string, qtype uint16, qtypePrefer uint16, hasRecords bool) bool {
	// Fast path: preference not enabled
	if qtypePrefer == 0 {
		return false
	}

	// Only A/AAAA responses
	if qtype != dnsmessage.TypeA && qtype != dnsmessage.TypeAAAA {
		return false
	}

	// Must be the preferred type
	if qtype != qtypePrefer {
		return false
	}

	r.mu.Lock()
	w, ok := r.waits[qname]
	if ok {
		// Mark the preferred response as observed before releasing the waiter.
		// A newer waiter may already have replaced this entry for the same
		// qname — notify it but only remove the identity we found.
		w.preferred = true
		w.preferredHasRecords = hasRecords
		close(w.done)
		if r.waits[qname] == w {
			delete(r.waits, qname)
		}
	}
	r.mu.Unlock()
	return ok
}

// remove removes a specific wait from the registry by identity. Removing by
// bare qname could delete a newer query's wait that reused the key after this
// one was replaced via registerWait's existing-wait return path.
func (r *preferenceWaitRegistry) remove(w *preferenceWait) {
	if w == nil {
		return
	}
	r.mu.Lock()
	if cur := r.waits[w.qname]; cur == w {
		delete(r.waits, w.qname)
	}
	r.mu.Unlock()
}

// waitFor waits for the preferred response or timeout.
// It returns whether the preferred response arrived before the timeout and, if
// it did, whether that response carried records of the preferred family.
func (w *preferenceWait) waitFor() (preferred bool, preferredHasRecords bool) {
	if w == nil {
		return false, false
	}

	deadline := w.deadline
	now := time.Now()

	if deadline.After(now) {
		// Wait for preferred response or timeout
		timeout := time.NewTimer(deadline.Sub(now))
		defer timeout.Stop()

		select {
		case <-w.done:
			// Preferred response arrived
			return w.preferred, w.preferredHasRecords
		case <-timeout.C:
			// Timeout, use original response
			return false, false
		}
	}

	// Already past deadline
	return false, false
}

// hasAddressRecords reports whether msg carries at least one answer record of
// the given address family. CNAME and other linkage records do not count: the
// caller uses this to decide whether a family really has an address to offer.
func hasAddressRecords(msg *dnsmessage.Msg, qtype uint16) bool {
	if msg == nil || (qtype != dnsmessage.TypeA && qtype != dnsmessage.TypeAAAA) {
		return false
	}
	for _, rr := range msg.Answer {
		if rr != nil && rr.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}

// isPreferredType returns true if qtype is the preferred A/AAAA type.
func isPreferredType(qtype uint16, qtypePrefer uint16) bool {
	if qtypePrefer == 0 {
		return false
	}
	return qtype == qtypePrefer
}
