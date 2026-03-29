package dialer

import (
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

// newRecoveryTestDialer is defined in deadlock_test.go

func TestProxyFailureThreshold(t *testing.T) {
	proxyAddr := "test-proxy.com:8080"
	globalProxyIpHealthTracker.Lock()
	globalProxyIpHealthTracker.failures = make(map[string]int32)
	globalProxyIpHealthTracker.Unlock()

	if recordProxyFailure(proxyAddr) { t.Error("Expected false after 1st failure") }
	if recordProxyFailure(proxyAddr) { t.Error("Expected false after 2nd failure") }
	if !recordProxyFailure(proxyAddr) { t.Error("Expected true after 3rd failure") }

	globalProxyIpHealthTracker.Lock()
	if _, exists := globalProxyIpHealthTracker.failures[proxyAddr]; exists {
		t.Error("Expected counter to be reset after threshold")
	}
	globalProxyIpHealthTracker.Unlock()
}

func TestRecoveryBackoffLevel(t *testing.T) {
	d := newRecoveryTestDialer()
	d.recoveryState[idxUdp].maxBackoff = 20 * time.Second

	testCases := []struct {
		level    int
		expected time.Duration
	}{
		{0, 10 * time.Second},
		{1, 20 * time.Second},
		{2, 20 * time.Second},
	}

	for _, tc := range testCases {
		d.recoveryState[idxUdp].backoffLevel = tc.level
		duration := d.getRecoveryBackoffDuration(consts.L4ProtoStr_UDP)
		if duration != tc.expected {
			t.Errorf("Level %d: expected %v, got %v", tc.level, tc.expected, duration)
		}
	}
}

func TestStabilityCountReset(t *testing.T) {
	d := newRecoveryTestDialer()
	d.recoveryState[idxUdp].backoffLevel = 3
	d.recoveryState[idxUdp].stableSuccessCount = 5

	// Reset should clear count but NOT level
	d.resetStabilityCount(consts.L4ProtoStr_UDP)

	if d.recoveryState[idxUdp].backoffLevel != 3 {
		t.Errorf("Expected level 3 points to persist, got %d", d.recoveryState[idxUdp].backoffLevel)
	}
	if d.recoveryState[idxUdp].stableSuccessCount != 0 {
		t.Errorf("Expected count 0 after reset, got %d", d.recoveryState[idxUdp].stableSuccessCount)
	}
}

func TestExponentialProgression(t *testing.T) {
	d := newRecoveryTestDialer()
	d.initRecoveryDetection(30 * time.Second)
	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}

	// 1st Recovery: level 0 -> 1
	d.NotifyHealthCheckResult(typ, true, true)
	d.confirmRecovery(typ)
	if d.GetBackoffLevel(consts.L4ProtoStr_TCP) != 1 {
		t.Errorf("Expected level 1, got %d", d.GetBackoffLevel(consts.L4ProtoStr_TCP))
	}

	// Failure doesn't reset level!
	d.NotifyHealthCheckResult(typ, false, false)
	if d.GetBackoffLevel(consts.L4ProtoStr_TCP) != 1 {
		t.Errorf("Expected level 1 to persist after failure, got %d", d.GetBackoffLevel(consts.L4ProtoStr_TCP))
	}

	// 2nd Recovery: level 1 -> 2
	d.NotifyHealthCheckResult(typ, true, true)
	d.confirmRecovery(typ)
	if d.GetBackoffLevel(consts.L4ProtoStr_TCP) != 2 {
		t.Errorf("Expected level 2, got %d", d.GetBackoffLevel(consts.L4ProtoStr_TCP))
	}
}

func TestNotifyPeriodicCheckResult_NewThreshold(t *testing.T) {
	d := newRecoveryTestDialer()
	d.initRecoveryDetection(30 * time.Second)
	proto := consts.L4ProtoStr_TCP

	d.recoveryState[idxTcp].backoffLevel = 2
	d.recoveryState[idxTcp].stableSuccessCount = 0

	// 1st success: count 1
	d.NotifyPeriodicCheckResult(proto, true, false)
	if d.recoveryState[idxTcp].stableSuccessCount != 1 {
		t.Errorf("Expected count 1, got %d", d.recoveryState[idxTcp].stableSuccessCount)
	}

	// 2nd success: level 2 -> 1, count 0
	d.NotifyPeriodicCheckResult(proto, true, false)
	if d.recoveryState[idxTcp].backoffLevel != 1 {
		t.Errorf("Expected level 1 after 2 successes, got %d", d.recoveryState[idxTcp].backoffLevel)
	}
	if d.recoveryState[idxTcp].stableSuccessCount != 0 {
		t.Error("Expected count reset")
	}
}

func TestRecoveryStateConcurrency(t *testing.T) {
	d := newRecoveryTestDialer()
	d.recoveryState[idxUdp].maxBackoff = 20 * time.Second
	var wg sync.WaitGroup
	iterations := 100
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			d.recoveryState[idxUdp].Lock()
			d.recoveryState[idxUdp].backoffLevel++
			d.recoveryState[idxUdp].Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			d.resetStabilityCount(consts.L4ProtoStr_UDP)
		}
	}()
	wg.Wait()
}

func BenchmarkGetRecoveryBackoffDuration(b *testing.B) {
	d := newRecoveryTestDialer()
	d.recoveryState[idxTcp].backoffLevel = 2
	d.recoveryState[idxTcp].maxBackoff = 20 * time.Second

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.getRecoveryBackoffDuration(consts.L4ProtoStr_TCP)
	}
}

func BenchmarkRecordProxyFailure(b *testing.B) {
	proxyAddr := "test-proxy.com:8080"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		globalProxyIpHealthTracker.Lock()
		globalProxyIpHealthTracker.failures[proxyAddr] = 0
		globalProxyIpHealthTracker.Unlock()
		recordProxyFailure(proxyAddr)
		recordProxyFailure(proxyAddr)
		recordProxyFailure(proxyAddr)
	}
}

func BenchmarkResetStabilityCount(b *testing.B) {
	d := newRecoveryTestDialer()
	d.recoveryState[idxTcp].backoffLevel = 5
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.resetStabilityCount(consts.L4ProtoStr_TCP)
	}
}
