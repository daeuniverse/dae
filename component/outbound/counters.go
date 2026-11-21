/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"sync"
	"sync/atomic"
	"time"
)

// Counters are the lifetime counters attributed to one outbound group. The
// counters live in a process-level registry keyed by the outbound name, so a
// reload that rebuilds the group with the same name keeps accumulating instead
// of starting over.
type Counters struct {
	activeConnections atomic.Int64
	totalConnections  atomic.Uint64
	uploadBytes       atomic.Uint64
	downloadBytes     atomic.Uint64
	errors            atomic.Uint64
}

// ActiveConnections returns the number of flows currently attributed to the
// outbound.
func (c *Counters) ActiveConnections() int64 {
	if c == nil {
		return 0
	}
	return c.activeConnections.Load()
}

// TotalConnections returns the number of flows established on the outbound.
func (c *Counters) TotalConnections() uint64 {
	if c == nil {
		return 0
	}
	return c.totalConnections.Load()
}

// UploadBytes returns the bytes sent from clients to the outbound.
func (c *Counters) UploadBytes() uint64 {
	if c == nil {
		return 0
	}
	return c.uploadBytes.Load()
}

// DownloadBytes returns the bytes received from the outbound.
func (c *Counters) DownloadBytes() uint64 {
	if c == nil {
		return 0
	}
	return c.downloadBytes.Load()
}

// Errors returns the failed dial attempts attributed to the outbound.
func (c *Counters) Errors() uint64 {
	if c == nil {
		return 0
	}
	return c.errors.Load()
}

// ConnectionEstablished records one established flow.
func (c *Counters) ConnectionEstablished() {
	if c == nil {
		return
	}
	c.totalConnections.Add(1)
	c.activeConnections.Add(1)
}

// ConnectionFinished records one flow leaving the outbound.
func (c *Counters) ConnectionFinished() {
	if c == nil {
		return
	}
	c.activeConnections.Add(-1)
}

// AddUpload accounts bytes travelling from the client to the outbound.
func (c *Counters) AddUpload(n uint64) {
	if c == nil || n == 0 {
		return
	}
	c.uploadBytes.Add(n)
}

// AddDownload accounts bytes travelling from the outbound to the client.
func (c *Counters) AddDownload(n uint64) {
	if c == nil || n == 0 {
		return
	}
	c.downloadBytes.Add(n)
}

// AddError records one failed dial attempt.
func (c *Counters) AddError() {
	if c == nil {
		return
	}
	c.errors.Add(1)
}

// CounterRegistry owns the per-outbound counters for one daemon process. The
// process session manager creates it, so its Since boundary matches the
// process lifetime and a reload keeps the same counters.
type CounterRegistry struct {
	mu      sync.RWMutex
	since   time.Time
	entries map[string]*Counters
}

// NewCounterRegistry constructs a registry whose counters start at now.
func NewCounterRegistry() *CounterRegistry {
	return &CounterRegistry{
		since:   time.Now(),
		entries: make(map[string]*Counters),
	}
}

// Since reports the shared counter reset boundary.
func (r *CounterRegistry) Since() time.Time {
	if r == nil {
		return time.Time{}
	}
	return r.since
}

// Acquire returns the counters for name, creating them on first use.
func (r *CounterRegistry) Acquire(name string) *Counters {
	if r == nil || name == "" {
		return nil
	}
	r.mu.RLock()
	counters := r.entries[name]
	r.mu.RUnlock()
	if counters != nil {
		return counters
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if counters = r.entries[name]; counters != nil {
		return counters
	}
	counters = &Counters{}
	r.entries[name] = counters
	return counters
}

// Lookup returns the counters for name without creating them.
func (r *CounterRegistry) Lookup(name string) *Counters {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.entries[name]
}
