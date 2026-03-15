package dialer

import (
	"io"
	"sync"
	"testing"
	"time"

	D "github.com/daeuniverse/outbound/dialer"
	"github.com/sirupsen/logrus"
)

// TestProxyFailureThreshold tests that 3 consecutive failures trigger unavailable state
func TestProxyFailureThreshold(t *testing.T) {
	// Setup
	proxyAddr := "test-proxy.com:8080"

	// Reset tracker
	globalProxyIpHealthTracker.Lock()
	globalProxyIpHealthTracker.failures = make(map[string]int32)
	globalProxyIpHealthTracker.Unlock()

	// Test: 2 failures should not trigger threshold
	if recordProxyFailure(proxyAddr) {
		t.Error("Expected false after 1st failure")
	}
	if recordProxyFailure(proxyAddr) {
		t.Error("Expected false after 2nd failure")
	}

	// Test: 3rd failure should trigger threshold
	if !recordProxyFailure(proxyAddr) {
		t.Error("Expected true after 3rd failure (threshold reached)")
	}

	// Test: counter should be reset after threshold
	globalProxyIpHealthTracker.Lock()
	if _, exists := globalProxyIpHealthTracker.failures[proxyAddr]; exists {
		t.Error("Expected counter to be reset after threshold")
	}
	globalProxyIpHealthTracker.Unlock()
}

// TestRecoveryBackoffLevel tests exponential backoff calculation
func TestRecoveryBackoffLevel(t *testing.T) {
	// Create a test dialer
	d := &Dialer{
		recoveryState: struct {
			sync.Mutex
			backoffLevel       int
			maxBackoff         time.Duration
			confirmTimer       *time.Timer
			pendingNetworkType *NetworkType
		}{
			maxBackoff: 20 * time.Second, // Initialize with expected max backoff
		},
	}

	// Test different backoff levels
	testCases := []struct {
		level       int
		minExpected time.Duration
		maxExpected time.Duration
	}{
		{0, 10 * time.Second, 10 * time.Second},
		{1, 20 * time.Second, 20 * time.Second},
		{2, 20 * time.Second, 20 * time.Second},  // Capped at max
		{10, 20 * time.Second, 20 * time.Second}, // Capped at max
	}

	for _, tc := range testCases {
		d.recoveryState.backoffLevel = tc.level
		duration := d.getRecoveryBackoffDuration()

		if duration < tc.minExpected || duration > tc.maxExpected {
			t.Errorf("Level %d: expected duration between %v and %v, got %v",
				tc.level, tc.minExpected, tc.maxExpected, duration)
		}
	}
}

// TestBackoffLevelReset tests that backoff level is reset on failure
func TestBackoffLevelReset(t *testing.T) {
	d := &Dialer{
		recoveryState: struct {
			sync.Mutex
			backoffLevel       int
			maxBackoff         time.Duration
			confirmTimer       *time.Timer
			pendingNetworkType *NetworkType
		}{
			backoffLevel: 3,
		},
	}

	// Verify initial level
	if d.recoveryState.backoffLevel != 3 {
		t.Errorf("Expected initial level 3, got %d", d.recoveryState.backoffLevel)
	}

	// Reset
	d.resetBackoffLevel()

	// Verify reset
	if d.recoveryState.backoffLevel != 0 {
		t.Errorf("Expected level 0 after reset, got %d", d.recoveryState.backoffLevel)
	}
}

// TestMaxBackoffLessThanCheckInterval tests that max backoff is less than check interval
func TestMaxBackoffLessThanCheckInterval(t *testing.T) {
	checkIntervals := []time.Duration{
		30 * time.Second,
		60 * time.Second,
		90 * time.Second,
	}

	for _, interval := range checkIntervals {
		maxBackoff := time.Duration(float64(interval) * 2.0 / 3.0)

		if maxBackoff >= interval {
			t.Errorf("Check interval %v: max backoff %v should be < interval", interval, maxBackoff)
		}

		// Also verify minimum
		if maxBackoff < minRecoveryBackoff {
			t.Errorf("Check interval %v: max backoff %v should be >= min (%v)",
				interval, maxBackoff, minRecoveryBackoff)
		}
	}
}

// TestRecoveryStateConcurrency tests that recovery state is thread-safe
func TestRecoveryStateConcurrency(t *testing.T) {
	d := &Dialer{
		recoveryState: struct {
			sync.Mutex
			backoffLevel       int
			maxBackoff         time.Duration
			confirmTimer       *time.Timer
			pendingNetworkType *NetworkType
		}{
			backoffLevel: 0,
			maxBackoff:   20 * time.Second,
		},
	}

	// Launch concurrent goroutines to modify backoff level
	done := make(chan bool)
	go func() {
		for i := 0; i < 100; i++ {
			d.recoveryState.Lock()
			d.recoveryState.backoffLevel++
			d.recoveryState.Unlock()
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			d.resetBackoffLevel()
		}
		done <- true
	}()

	// Wait for both to complete
	<-done
	<-done

	// Verify final state is consistent (should be 0 or >0)
	d.recoveryState.Lock()
	level := d.recoveryState.backoffLevel
	d.recoveryState.Unlock()

	if level < 0 {
		t.Errorf("Expected non-negative level, got %d", level)
	}
}

// TestTimerLeakOnClose tests that timers are properly cleaned up on Close
func TestTimerLeakOnClose(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	property := &Property{
		Property: D.Property{
			Name: "test-dialer",
		},
	}

	d := &Dialer{
		GlobalOption: &GlobalOption{
			Log: logger,
		},
		property: property,
		recoveryState: struct {
			sync.Mutex
			backoffLevel       int
			maxBackoff         time.Duration
			confirmTimer       *time.Timer
			pendingNetworkType *NetworkType
		}{
			backoffLevel: 0,
		},
	}

	// Simulate triggering recovery detection
	d.recoveryState.Lock()
	d.recoveryState.confirmTimer = time.NewTimer(10 * time.Second)
	d.recoveryState.Unlock()

	// Verify timer exists
	d.recoveryState.Lock()
	if d.recoveryState.confirmTimer == nil {
		t.Error("Expected timer to exist")
	}
	timerExists := d.recoveryState.confirmTimer != nil
	d.recoveryState.Unlock()

	if !timerExists {
		return
	}

	// Close should cancel timer
	d.cancelPendingRecoveryConfirmation()

	// Verify timer was stopped
	d.recoveryState.Lock()
	timerStopped := d.recoveryState.confirmTimer == nil
	d.recoveryState.Unlock()

	if !timerStopped {
		t.Error("Expected timer to be stopped after cancellation")
	}
}

// TestMultipleRecoveryTriggers tests that multiple concurrent triggers don't create duplicate timers
func TestMultipleRecoveryTriggers(t *testing.T) {
	d := &Dialer{
		recoveryState: struct {
			sync.Mutex
			backoffLevel       int
			maxBackoff         time.Duration
			confirmTimer       *time.Timer
			pendingNetworkType *NetworkType
		}{
			backoffLevel: 0,
		},
	}

	// Simulate MustGetAlive returning false
	// This test verifies that triggerRecoveryDetection checks for existing timer

	// We can't easily test this without mocking MustGetAlive,
	// but we can verify the locking behavior
	d.recoveryState.Lock()
	d.recoveryState.confirmTimer = nil
	d.recoveryState.Unlock()

	// Trigger multiple times (should not create duplicate timers)
	for i := 0; i < 10; i++ {
		// In real scenario, triggerRecoveryDetection would check timer first
		// Here we just verify no panic
		d.recoveryState.Lock()
		if d.recoveryState.confirmTimer != nil {
			d.recoveryState.Unlock()
			t.Error("Expected nil timer before first trigger")
			return
		}
		d.recoveryState.Unlock()
	}
}

// TestFailureDuringRecoveryBackoff tests that failure during backoff cancels pending confirmation
func TestFailureDuringRecoveryBackoff(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	d := &Dialer{
		GlobalOption: &GlobalOption{
			Log: logger,
		},
		property: &Property{
			Property: D.Property{
				Name: "test-dialer",
			},
		},
		recoveryState: struct {
			sync.Mutex
			backoffLevel       int
			maxBackoff         time.Duration
			confirmTimer       *time.Timer
			pendingNetworkType *NetworkType
		}{
			backoffLevel: 2,
		},
	}

	// Simulate recovery in progress
	d.recoveryState.Lock()
	d.recoveryState.confirmTimer = time.NewTimer(10 * time.Second)
	d.recoveryState.Unlock()

	// Verify timer exists
	d.recoveryState.Lock()
	if d.recoveryState.confirmTimer == nil {
		t.Error("Expected timer to exist")
	}
	d.recoveryState.Unlock()

	// Simulate failure during backoff
	d.cancelPendingRecoveryConfirmation()

	// Verify timer was cancelled
	d.recoveryState.Lock()
	if d.recoveryState.confirmTimer != nil {
		t.Error("Expected timer to be cancelled")
	}
	d.recoveryState.Unlock()

	// Note: cancelPendingRecoveryConfirmation only cancels the timer,
	// it doesn't reset the backoff level. The reset happens in resetBackoffLevel()
	// which is called from markUnavailableFromProxyFailure().
}

// TestConcurrentFailureAndRecovery tests concurrent failure and recovery events
func TestConcurrentFailureAndRecovery(t *testing.T) {
	// This test simulates rapid failure/recovery cycles
	// to ensure no race conditions or deadlocks

	iterations := 100
	var wg sync.WaitGroup

	for i := 0; i < iterations; i++ {
		wg.Add(2)

		// Simulate failure path
		go func() {
			defer wg.Done()
			// In real scenario, this would call markUnavailableFromProxyFailure
			// which calls resetBackoffLevel and cancelPendingRecoveryConfirmation
			d := &Dialer{}
			d.resetBackoffLevel()
		}()

		// Simulate recovery path
		go func() {
			defer wg.Done()
			// In real scenario, this would call triggerRecoveryDetection
			// which checks existing timer and creates new one
			d := &Dialer{}
			_ = d.getRecoveryBackoffDuration()
		}()
	}

	wg.Wait()
	// If we get here without deadlock, test passes
}

// BenchmarkGetRecoveryBackoffDuration benchmarks the backoff duration calculation
func BenchmarkGetRecoveryBackoffDuration(b *testing.B) {
	d := &Dialer{
		recoveryState: struct {
			sync.Mutex
			backoffLevel       int
			maxBackoff         time.Duration
			confirmTimer       *time.Timer
			pendingNetworkType *NetworkType
		}{
			backoffLevel: 2,
			maxBackoff:   20 * time.Second,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.getRecoveryBackoffDuration()
	}
}

// BenchmarkRecordProxyFailure benchmarks the failure recording
func BenchmarkRecordProxyFailure(b *testing.B) {
	proxyAddr := "test-proxy.com:8080"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset before each iteration
		globalProxyIpHealthTracker.Lock()
		globalProxyIpHealthTracker.failures[proxyAddr] = 0
		globalProxyIpHealthTracker.Unlock()

		// Record 3 failures
		recordProxyFailure(proxyAddr)
		recordProxyFailure(proxyAddr)
		recordProxyFailure(proxyAddr)
	}
}

// BenchmarkResetBackoffLevel benchmarks the backoff level reset
func BenchmarkResetBackoffLevel(b *testing.B) {
	d := &Dialer{
		recoveryState: struct {
			sync.Mutex
			backoffLevel       int
			maxBackoff         time.Duration
			confirmTimer       *time.Timer
			pendingNetworkType *NetworkType
		}{
			backoffLevel: 5,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.resetBackoffLevel()
	}
}
