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
	resetGlobalProxyState()

	if recordProxyFailure(proxyAddr) {
		t.Error("Expected false after 1st failure")
	}
	if recordProxyFailure(proxyAddr) {
		t.Error("Expected false after 2nd failure")
	}
	if !recordProxyFailure(proxyAddr) {
		t.Error("Expected true after 3rd failure")
	}

	globalProxyIpHealthTracker.Lock()
	if _, exists := globalProxyIpHealthTracker.failures[proxyAddr]; exists {
		t.Error("Expected counter to be reset after threshold")
	}
	globalProxyIpHealthTracker.Unlock()
}

func TestRecoveryBackoffLevel(t *testing.T) {
	d := newRecoveryTestDialer()
	d.recoveryState[idxDnsUdp].maxBackoff = 20 * time.Second

	testCases := []struct {
		level    int
		expected time.Duration
	}{
		{0, 10 * time.Second},
		{1, 20 * time.Second},
		{2, 20 * time.Second},
	}

	for _, tc := range testCases {
		d.recoveryState[idxDnsUdp].backoffLevel = tc.level
		duration := d.getRecoveryBackoffDuration(consts.L4ProtoStr_UDP)
		if duration != tc.expected {
			t.Errorf("Level %d: expected %v, got %v", tc.level, tc.expected, duration)
		}
	}
}

func TestStabilityCountReset(t *testing.T) {
	d := newRecoveryTestDialer()
	d.recoveryState[idxDnsUdp].backoffLevel = 3
	d.recoveryState[idxDnsUdp].stableSuccessCount = 5

	// Reset should clear count but NOT level
	d.resetStabilityCount(consts.L4ProtoStr_UDP)

	if d.recoveryState[idxDnsUdp].backoffLevel != 3 {
		t.Errorf("Expected level 3 points to persist, got %d", d.recoveryState[idxDnsUdp].backoffLevel)
	}
	if d.recoveryState[idxDnsUdp].stableSuccessCount != 0 {
		t.Errorf("Expected count 0 after reset, got %d", d.recoveryState[idxDnsUdp].stableSuccessCount)
	}
}

func TestRevivalTrigger(t *testing.T) {
	d := newRecoveryTestDialer()
	d.CheckInterval = 30 * time.Second
	d.initRecoveryDetection(30 * time.Second)

	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}

	// 1. Success with isRevival=false should NOT start timer
	d.NotifyHealthCheckResult(typ, true, false)
	d.recoveryState[idxTcp].Lock()
	if d.recoveryState[idxTcp].confirmTimer != nil {
		d.recoveryState[idxTcp].Unlock()
		t.Error("Timer started on non-revival success")
	}
	d.recoveryState[idxTcp].Unlock()

	// 2. Success with isRevival=true SHOULD start timer
	// Note: in new logic, we must be careful. NotifyHealthCheckResult(true, true) starts timer regardless of current state
	// as long as isRevival=true is passed.
	d.NotifyHealthCheckResult(typ, true, true)
	d.recoveryState[idxTcp].Lock()
	if d.recoveryState[idxTcp].confirmTimer == nil {
		d.recoveryState[idxTcp].Unlock()
		t.Error("Timer NOT started on revival success")
	} else {
		d.recoveryState[idxTcp].confirmTimer.Stop()
		d.recoveryState[idxTcp].confirmTimer = nil
	}
	d.recoveryState[idxTcp].Unlock()
}

func TestExponentialProgression(t *testing.T) {
	d := newRecoveryTestDialer()
	d.initRecoveryDetection(30 * time.Second)
	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}

	// 1st Failure: level 0 -> 1
	d.NotifyHealthCheckResult(typ, false, false)
	if d.GetBackoffLevel(consts.L4ProtoStr_TCP) != 1 {
		t.Errorf("Expected level 1 after failure, got %d", d.GetBackoffLevel(consts.L4ProtoStr_TCP))
	}

	// Recovery: level 1 -> 0
	d.NotifyHealthCheckResult(typ, true, true)
	d.confirmRecovery(typ, nil)
	if d.GetBackoffLevel(consts.L4ProtoStr_TCP) != 0 {
		t.Errorf("Expected level 0 after recovery, got %d", d.GetBackoffLevel(consts.L4ProtoStr_TCP))
	}

	// 2nd Failure: level 0 -> 1
	d.lastPunish[idxTcp].Store(0)
	d.NotifyHealthCheckResult(typ, false, false)
	// 3rd Failure: level 1 -> 2
	d.lastPunish[idxTcp].Store(0)
	d.NotifyHealthCheckResult(typ, false, false)
	if d.GetBackoffLevel(consts.L4ProtoStr_TCP) != 2 {
		t.Errorf("Expected level 2 after multiple failures, got %d", d.GetBackoffLevel(consts.L4ProtoStr_TCP))
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
	d.recoveryState[idxDnsUdp].maxBackoff = 20 * time.Second
	var wg sync.WaitGroup
	iterations := 100
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			d.recoveryState[idxDnsUdp].Lock()
			d.recoveryState[idxDnsUdp].backoffLevel++
			d.recoveryState[idxDnsUdp].Unlock()
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
		globalProxyIpHealthTracker.failures[proxyAddr] = proxyIpFailureEntry{}
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
