/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"strings"
	"sync"
	"time"
)

const (
	defaultOffset = 2
	// FakeIPTTL is the default TTL for fakeip entries (1 hour)
	FakeIPTTL = 1 * time.Hour
	// FakeIPCleanupInterval is the execution interval for cleanup tasks (10 minutes)
	FakeIPCleanupInterval = 10 * time.Minute
)

// fakeipEntry represents a fakeip entry
type fakeipEntry struct {
	ip         net.IP
	domain     string
	expireTime time.Time
}

// fakeipPool is a fakeip pool implementation with automatic cleanup
// Uses the 198.18.0.0/16 address range as the fakeip pool
type fakeipPool struct {
	mu            sync.RWMutex
	domainToEntry map[string]*fakeipEntry // mapping from domain to entry
	ipToDomain    map[string]string       // reverse mapping from IP to domain
	baseIP        net.IP                  // base IP address (198.18.0.0)
	currentOffset uint32                  // current allocation offset
	maxOffset     uint32                  // maximum offset (65536)
	ttl           time.Duration           // TTL for entries
	stopChan      chan struct{}           // channel to stop cleanup goroutine
	cleanupTicker *time.Ticker            // cleanup ticker
}

var (
	globalFakeipPool     *fakeipPool
	globalFakeipPoolOnce sync.Once
)

// GetGlobalFakeipPool returns the global fakeip pool singleton
func GetGlobalFakeipPool() *fakeipPool {
	globalFakeipPoolOnce.Do(func() {
		globalFakeipPool = newFakeipPool()
		globalFakeipPool.startCleanup()
	})
	return globalFakeipPool
}

// newFakeipPool creates a new fakeip pool
func newFakeipPool() *fakeipPool {
	return &fakeipPool{
		domainToEntry: make(map[string]*fakeipEntry),
		ipToDomain:    make(map[string]string),
		baseIP:        net.ParseIP("198.18.0.0").To4(),
		maxOffset:     65536, // 198.18.0.0/16 can allocate 65536 addresses
		ttl:           FakeIPTTL,
		stopChan:      make(chan struct{}),
		currentOffset: defaultOffset,
	}
}

// startCleanup starts the automatic cleanup goroutine
func (p *fakeipPool) startCleanup() {
	p.cleanupTicker = time.NewTicker(FakeIPCleanupInterval)
	go p.cleanupLoop()
}

// cleanupLoop runs the cleanup loop
func (p *fakeipPool) cleanupLoop() {
	for {
		select {
		case <-p.cleanupTicker.C:
			p.cleanup()
		case <-p.stopChan:
			p.cleanupTicker.Stop()
			return
		}
	}
}

// cleanup removes expired entries
func (p *fakeipPool) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	expiredDomains := make([]string, 0)

	// find all expired domains
	for domain, entry := range p.domainToEntry {
		if now.After(entry.expireTime) {
			expiredDomains = append(expiredDomains, domain)
		}
	}

	// delete expired entries
	for _, domain := range expiredDomains {
		if entry, exists := p.domainToEntry[domain]; exists {
			delete(p.ipToDomain, entry.ip.String())
			delete(p.domainToEntry, domain)
		}
	}
}

// Stop stops the cleanup goroutine
func (p *fakeipPool) Stop() {
	close(p.stopChan)
}

// allocate assigns a fake IP address to a domain
func (p *fakeipPool) allocate(domain string) net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()

	// if the domain already has an IP, update expiration time and return
	if entry, exists := p.domainToEntry[domain]; exists {
		entry.expireTime = now.Add(p.ttl)
		return entry.ip
	}

	// allocate a new IP
	offset := p.currentOffset
	p.currentOffset++
	if p.currentOffset >= p.maxOffset {
		p.currentOffset = defaultOffset
	}

	// calculate IP address: 198.18.0.0 + offset
	ip := make(net.IP, 4)
	copy(ip, p.baseIP)
	ip[2] = byte(offset >> 8)
	ip[3] = byte(offset & 0xff)

	// create new entry
	entry := &fakeipEntry{
		ip:         ip,
		domain:     domain,
		expireTime: now.Add(p.ttl),
	}

	// if this IP is already occupied, clean up the old mapping first
	ipStr := ip.String()
	if oldDomain, exists := p.ipToDomain[ipStr]; exists {
		delete(p.domainToEntry, oldDomain)
	}

	// save mapping relationships
	p.domainToEntry[domain] = entry
	p.ipToDomain[ipStr] = domain

	return ip
}

// lookup finds the corresponding domain for a fake IP
func (p *fakeipPool) lookup(ip net.IP) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	domain, exists := p.ipToDomain[ip.String()]
	if !exists {
		return "", false
	}

	// check if expired
	if entry, ok := p.domainToEntry[domain]; ok {
		if time.Now().After(entry.expireTime) {
			return "", false
		}
	}
	if strings.HasSuffix(domain, ".") {
		return domain[:len(domain)-1], true
	}

	return domain, true
}

// GetStats returns pool statistics
func (p *fakeipPool) GetStats() (total int, allocated int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return int(p.maxOffset), len(p.domainToEntry)
}
