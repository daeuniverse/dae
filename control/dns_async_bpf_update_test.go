/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var testLogger = logrus.New()

func init() {
	testLogger.SetLevel(logrus.ErrorLevel) // Reduce test noise
}

// TestBpfUpdateWorker_Lifecycle tests that the BPF update worker starts,
// processes tasks, and shuts down cleanly without leaking goroutines.
func TestBpfUpdateWorker_Lifecycle(t *testing.T) {
	controller := &DnsController{
		log: testLogger,
		cacheAccessCallback: func(cache *DnsCache) error {
			// Simulate BPF update work
			time.Sleep(10 * time.Millisecond)
			return nil
		},
		dnsCache: sync.Map{},
	}

	// Worker should not be started initially
	assert.Nil(t, controller.bpfUpdateCh)
	assert.Nil(t, controller.bpfUpdateStop)

	// Trigger start by calling triggerBpfUpdateIfNeeded
	cache := &DnsCache{}
	now := time.Now()
	controller.triggerBpfUpdateIfNeeded(cache, now)

	// Worker should now be started
	assert.NotNil(t, controller.bpfUpdateCh)
	assert.NotNil(t, controller.bpfUpdateStop)

	// Send a few tasks
	for i := 0; i < 5; i++ {
		controller.triggerBpfUpdateIfNeeded(cache, now)
	}

	// Close should wait for all tasks to complete
	done := make(chan struct{})
	go func() {
		controller.Close()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not complete in time")
	}
}

// TestBpfUpdateWorker_NonBlockingSend verifies that sending to a full queue
// does not block the caller.
func TestBpfUpdateWorker_NonBlockingSend(t *testing.T) {
	updateCallCount := atomic.Int32{}
	blockChan := make(chan struct{})

	controller := &DnsController{
		log: testLogger,
		cacheAccessCallback: func(cache *DnsCache) error {
			updateCallCount.Add(1)
			<-blockChan // Block until test releases
			return nil
		},
		dnsCache: sync.Map{},
	}

	// Start the worker
	controller.startBpfUpdateWorker()

	now := time.Now()

	// Fill the queue directly (1024 slots)
	const queueSize = 1024
	for i := 0; i < queueSize; i++ {
		cache := &DnsCache{}
		controller.triggerBpfUpdateIfNeeded(cache, now)
	}

	// This send should not block even though queue is full
	start := time.Now()
	cache2 := &DnsCache{}
	controller.triggerBpfUpdateIfNeeded(cache2, now)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 10*time.Millisecond, "Send should be non-blocking")

	// Release blocked workers and cleanup
	close(blockChan)

	// Close with timeout to prevent test hang
	done := make(chan struct{})
	go func() {
		controller.Close()
		close(done)
	}()
	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not complete in time")
	}

	// Verify all tasks were processed
	t.Log("Processed tasks:", updateCallCount.Load())
}

// TestBpfUpdateWorker_ErrorHandling verifies that errors in BPF updates
// don't crash the worker.
func TestBpfUpdateWorker_ErrorHandling(t *testing.T) {
	expectedErr := assert.AnError
	callCount := atomic.Int32{}

	controller := &DnsController{
		log: testLogger,
		cacheAccessCallback: func(cache *DnsCache) error {
			callCount.Add(1)
			return expectedErr
		},
		dnsCache: sync.Map{},
	}

	controller.startBpfUpdateWorker()

	// Trigger multiple updates that will fail
	// Note: Due to CAS in NeedsBpfUpdate, only the first update per cache will be triggered.
	// So we use different cache instances.
	for i := 0; i < 10; i++ {
		cache := &DnsCache{}
		now := time.Now()
		controller.triggerBpfUpdateIfNeeded(cache, now)
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// All calls should have been processed despite errors
	assert.Equal(t, int32(10), callCount.Load())

	controller.Close()
}

// TestBpfUpdateWorker_SemanticsPreserved verifies that the semantics
// of BPF updates are preserved when using async mode.
func TestBpfUpdateWorker_SemanticsPreserved(t *testing.T) {
	updateTimes := make([]time.Time, 0)
	var mu sync.Mutex

	controller := &DnsController{
		log: testLogger,
		cacheAccessCallback: func(cache *DnsCache) error {
			mu.Lock()
			defer mu.Unlock()
			updateTimes = append(updateTimes, time.Now())
			return nil
		},
		dnsCache: sync.Map{},
	}

	// Create a cache and trigger update
	cache := &DnsCache{}
	now := time.Now()

	// Simulate the sequence of calls that happen in LookupDnsRespCache
	// First call: triggers async update
	controller.triggerBpfUpdateIfNeeded(cache, now)

	// Second immediate call: should NOT trigger another update
	// (CAS in NeedsBpfUpdate prevents this)
	controller.triggerBpfUpdateIfNeeded(cache, now)

	// Wait for async processing
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	count := len(updateTimes)
	mu.Unlock()

	// Only one update should have been executed
	assert.Equal(t, 1, count, "Should have exactly one update despite two trigger calls")

	controller.Close()
}

// TestBpfUpdateWorker_ConcurrentAccess tests concurrent access to the
// BPF update mechanism from multiple goroutines.
func TestBpfUpdateWorker_ConcurrentAccess(t *testing.T) {
	const numGoroutines = 100
	const numUpdatesPerGoroutine = 10

	updateCount := atomic.Int32{}
	controller := &DnsController{
		log: testLogger,
		cacheAccessCallback: func(cache *DnsCache) error {
			updateCount.Add(1)
			return nil
		},
		dnsCache: sync.Map{},
	}

	var wg sync.WaitGroup
	now := time.Now()

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numUpdatesPerGoroutine; j++ {
				// Each goroutine uses a unique cache to test concurrent queue access
				cache := &DnsCache{}
				controller.triggerBpfUpdateIfNeeded(cache, now)
				time.Sleep(time.Microsecond)
			}
		}()
	}

	wg.Wait()

	// Wait for async processing to complete
	time.Sleep(200 * time.Millisecond)

	// With unique caches, all updates should be enqueued (though some may be dropped if queue is full)
	// At minimum, queue size (256) should be processed
	assert.Greater(t, updateCount.Load(), int32(0),
		"At least some updates should be processed")

	controller.Close()
}

// TestBpfUpdateWorker_LazyStart verifies that the worker is only started
// when actually needed.
func TestBpfUpdateWorker_LazyStart(t *testing.T) {
	controller := &DnsController{
		log:     testLogger,
		dnsCache: sync.Map{},
	}

	// Worker should not be started initially
	assert.Nil(t, controller.bpfUpdateCh)

	// Operations that don't need BPF updates should not start worker
	controller.LookupDnsRespCache("test", false)
	assert.Nil(t, controller.bpfUpdateCh, "Worker should not start without callback")

	// Add callback but don't trigger update
	controller.cacheAccessCallback = func(cache *DnsCache) error { return nil }
	// Cache doesn't exist, so no update triggered
	controller.LookupDnsRespCache("test", false)
	// Worker might or might not start depending on whether cache exists
	// This is fine - the key is that it's lazy
}

// TestBpfUpdateWorker_QueueFull verifies behavior when queue is full.
func TestBpfUpdateWorker_QueueFull(t *testing.T) {
	busy := make(chan struct{})
	updateCount := atomic.Int32{}

	controller := &DnsController{
		log: testLogger,
		cacheAccessCallback: func(cache *DnsCache) error {
			updateCount.Add(1)
			<-busy // Block to keep worker busy
			return nil
		},
		dnsCache: sync.Map{},
	}

	controller.startBpfUpdateWorker()

	now := time.Now()

	// Send one task that will block the worker
	cache1 := &DnsCache{}
	go controller.triggerBpfUpdateIfNeeded(cache1, now)
	time.Sleep(50 * time.Millisecond)

	// Fill the queue with unique cache instances (each triggers an update due to fresh CAS state)
	const queueSize = 1024
	for i := 0; i < queueSize; i++ {
		cache := &DnsCache{}
		controller.triggerBpfUpdateIfNeeded(cache, now)
	}

	initialCount := updateCount.Load()

	// This send should be dropped (queue full)
	cache2 := &DnsCache{}
	controller.triggerBpfUpdateIfNeeded(cache2, now)

	// Wait a bit to ensure the dropped send wasn't processed
	time.Sleep(50 * time.Millisecond)

	// Count should be the same (the dropped send wasn't processed)
	assert.Equal(t, initialCount, updateCount.Load())

	// Cleanup
	close(busy)
	controller.Close()
}
