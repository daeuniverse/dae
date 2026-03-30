/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
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
	qtype     uint16        // Original query type (A or AAAA)
	preferred bool          // Whether the preferred response arrived in time
	done      chan struct{} // Closed when wait is complete (timeout or preferred arrived)
	deadline  time.Time     // Wait deadline
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
		qtype:    qtype,
		done:     make(chan struct{}),
		deadline: time.Now().Add(PreferenceResolutionDelay),
	}
	r.waits[qname] = w
	return w
}

// notifyPreferred notifies a waiting query that the preferred response has arrived.
// Returns true if a waiter was found and notified.
func (r *preferenceWaitRegistry) notifyPreferred(qname string, qtype uint16, qtypePrefer uint16) bool {
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
		w.preferred = true
		close(w.done)
		delete(r.waits, qname)
	}
	r.mu.Unlock()
	return ok
}

// remove removes a wait from the registry.
func (r *preferenceWaitRegistry) remove(qname string) {
	r.mu.Lock()
	delete(r.waits, qname)
	r.mu.Unlock()
}

// waitFor waits for the preferred response or timeout.
// Returns true if the preferred response arrived before the timeout.
func (w *preferenceWait) waitFor() (preferred bool) {
	if w == nil {
		return false
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
			return w.preferred
		case <-timeout.C:
			// Timeout, use original response
			return false
		}
	}

	// Already past deadline
	return false
}

// isPreferredType returns true if qtype is the preferred A/AAAA type.
func isPreferredType(qtype uint16, qtypePrefer uint16) bool {
	if qtypePrefer == 0 {
		return false
	}
	return qtype == qtypePrefer
}
